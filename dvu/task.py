# Python imports
import logging

# Project imports
from config.celery_app import app
from .models import SyncQueue
from .ssh_file import SshUtil

logger = logging.getLogger(__name__)


@app.task(soft_time_limit=7200)
def data_transfer_task():
    logger.info('Checking if process already running')
    if SyncQueue.objects.filter(status=SyncQueue.pushing_to_destination).exists():
        logger.info('Process Already running')
    else:
        logger.info('No running process')
        logger.info("Checking for pending transfer")
        jobs = SyncQueue.objects.filter(status=SyncQueue.pending)
        if jobs.exists():
            logger.info("Found pending transfer")
            job = jobs.first()
            job.status = SyncQueue.pushing_to_destination
            job.save()

            ssh_obj = SshUtil(job)

            if job.sync_type == SyncQueue.asset:
                result, output = ssh_obj.transfer_assets()
            else:
                result, output = ssh_obj.transfer_database()

            if result:
                job.status = SyncQueue.push_complete
                # logger.info(result, output)
            else:
                job.status = SyncQueue.push_failed
                # logger.error(result, output)

            job.output = output
            job.save()
