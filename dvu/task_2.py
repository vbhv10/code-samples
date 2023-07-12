# Python Imports
import os
import weasyprint
import logging
import contextlib
from datetime import datetime

# Django Imports
from django.template.loader import get_template
from django.db import transaction

# Project Imports
from .models import Verification, ServerConfiguration, ServerName, Email, Commands, EmailQueue
from .ssh_file import SshUtil
from .utils import send_email
from config.celery_app import app
from config.settings.base import APPS_DIR

logger = logging.getLogger(__name__)


class Render:
    """
    - render html
    - convert it to pdf and save to local server
    - email the pdf with default and given email ids
    - remove pdf from local server
    """

    def __init__(self, obj):
        self.to = obj.to.split(",") if obj.to else []
        self.cc = obj.cc.split(",") if obj.cc else []
        self.bcc = obj.bcc.split(",") if obj.bcc else []
        self.subject = obj.subject
        self.message = obj.message

    def render(self, path: str, params: dict, email_obj):
        """
        Send the generated pdf in email to the recipients.

        :param email_obj: object od EmailQueue.
        :param path: path to pdf file in server.
        :param params: params that need to be given to render html.
        :return: None
        """

        params.update(date=datetime.today().strftime('%d/%m/%Y'))
        html = get_template(path).render(params)
        url = '/app/dvu/media/report/' + params.get('server').get_pdf_name() + '.pdf'
        if email_obj.to:
            self.to.extend(email_obj.to.split(","))
        if email_obj.cc:
            self.cc.extend(email_obj.cc.split(","))
        if email_obj.bcc:
            self.bcc.extend(email_obj.bcc.split(","))
        if email_obj.message:
            self.message = email_obj.message
        if email_obj.subject:
            self.subject = email_obj.subject
        elif not self.subject:
            self.subject = "Server-Verification-{}".format(params.get('server').name)
        if not os.path.exists('dvu/media/report'):
            os.mkdir('dvu/media/report')

        css = [weasyprint.CSS(str(APPS_DIR)+"/static/css/pdf.css")]

        try:
            pdf = weasyprint.HTML(string=html).write_pdf(stylesheets=css, presentational_hints=True)
            open(url, 'wb').write(pdf)
        except Exception as e:
            logger.info(str(e))
            pass

        status_flag, response = send_email(self.to, self.subject, cc=self.cc, bcc=self.bcc, body=self.message,
                                           file_path=url)
        if status_flag:
            email_obj.status = EmailQueue.success
            email_obj.response = response
        else:
            email_obj.status = EmailQueue.failed
            email_obj.response = response

        email_obj.save()
        with contextlib.suppress(FileNotFoundError, UnboundLocalError):
            os.remove(url)


@app.task
def verification_task():
    """
    Async task function to run server verification.

    :return: runs verification task by ssh over server.
    """
    logger.info('Checking if process already running')
    if Verification.objects.filter(status='RUNNING').exists():
        logger.info('Process Already running')
    else:
        logger.info('No running process')
        logger.info("Checking for pending jobs")
        pending_jobs = Verification.objects.filter(status='PENDING')
        if pending_jobs.exists():
            logger.info("Found pending jobs")

            pending_jobs.filter(server_config=pending_jobs.first().server_config).update(status='RUNNING')

            running_jobs = Verification.objects.filter(status='RUNNING')
            ssh_obj = SshUtil(running_jobs.first())

            if running_jobs.first().server_config.server == "DATABASE":
                ssh_obj.execute_query(running_jobs)
            else:
                ssh_obj.execute_command(running_jobs)

        else:
            logger.debug("No pending Verifications Found")


@app.task
def email_task(server_id, email_data, server_data=None, create_config=False, is_production=False):
    """
    :param create_config: if True then function will create configurations first
    :param server_id: server id
    :param email_data: email data in API
    :param server_data: server data in API
    :param is_production: if server is staging or production.
    :return: delete and recreate server configurations and call verification_task

    - check verification_task() after this
    """
    with transaction.atomic():
        server_name = ServerName.objects.get(id=server_id)
        if create_config:
            for server in server_data:
                ServerConfiguration.objects.filter(server=server.get("type"), name=server_name).delete()
                if server.get("type") == "DATABASE":
                    ServerConfiguration.objects.create(name=server_name, server=server.get("type"),
                                                       host=server.get("hostname"),
                                                       username=server.get("username"),
                                                       password=server.get("password"),
                                                       key=None, port=server.get("port"))
                else:
                    key = None
                    if not server["password"]:
                        if is_production:
                            key = "/production/.key_production"
                        else:
                            key = "/stagging/.key_stagging"

                    if server.get("hostname"):
                        ServerConfiguration.objects.create(name=server_name, server=server.get("type"),
                                                           host=server.get("hostname"),
                                                           username=server.get("username"),
                                                           password=server.get("password"), key=key,
                                                           port=server.get("port"),
                                                           is_production=is_production)
            logger.info("Details created on API call")

        for server_config in list(ServerConfiguration.objects.filter(name=server_name)):

            commands = Commands.objects.filter(server=server_config.server)
            Verification.objects.filter(server_config=server_config).delete()

            for command in commands:
                verify = Verification(server_config=server_config, command=command.command, name=command.name,
                                      status='PENDING')
                verify.save()

        for data in email_data:
            EmailQueue.objects.create(server=server_name, to=",".join(data["to"]), cc=",".join(data["cc"]),
                                      bcc=",".join(data["bcc"]), message=data["message"], subject=data["subject"],
                                      status=EmailQueue.pending,
                                      pdf_type=EmailQueue.detailed if data["detailed"] else EmailQueue.abstract)
        verification_task.apply_async()
        # verification_task()


@app.task
def send_email_task():
    """
    Async task function to email report.

    :return: None.
    """
    logger.info('Checking for running mails')
    if EmailQueue.objects.filter(status=EmailQueue.running).exists():
        logger.info('Process Already running')
    else:
        logger.info('No running mails')
        logger.info("Checking for pending mails")
        pending_mails = EmailQueue.objects.filter(status=EmailQueue.pending)
        if pending_mails.exists():
            logger.info("Found pending mails")

            for mail in pending_mails:
                if not Verification.objects.filter(server_config__name=mail.server,
                                                   status__in=["PENDING", "RUNNING"]).exists():
                    mail.status = EmailQueue.running
                    mail.save()

                    server_list = sorted(list(ServerConfiguration.objects.filter(name=mail.server).values_list(
                        'server', flat=True)))
                    verification_list = Verification.objects.filter(server_config__name=mail.server)
                    template_render = Render(Email.load())
                    template = 'pages/verification/pdf_template.html' if mail.pdf_type == EmailQueue.detailed \
                        else 'pages/verification/pdf_template_simple.html'

                    template_render.render(template, {
                        'servers_list': server_list,
                        'server': mail.server,
                        'verification_list': verification_list,
                    }, email_obj=mail)
