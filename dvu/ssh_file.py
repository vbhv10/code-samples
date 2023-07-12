# Python Imports
import json
import logging
import os
import re
import socket
import subprocess
import sys
import requests
import contextlib
import tarfile
import shutil
import paramiko
import pymysql
from stat import S_ISDIR, S_ISREG

# Project Imports
from config.settings.base import MEDIA_ROOT, VAULT_PASSWORD, VAULT_PATH, VAULT_URL, VALUT_USER
from .variables import *

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
logger = logging.getLogger(__name__)


def get_hotel(output, code=False):
    data = output.split("\n")[1].split("\t")
    if code:
        return data
    return data[0]


def get_his_url(output):
    return output.split("\n")[1]


def get_path(path, hotel_id):
    return path.replace("/{{hotel_id}}", hotel_id)


def get_file_name(startswith, files, extension=None, names=False):
    if files:
        files = sorted(list(filter(lambda x: re.search(r'\d', x) and x.startswith(startswith), files)),
                       key=lambda x: int(re.search(r'\d+(?=\.)', x).group(0)))
    else:
        files = []
    if names:
        return files
    return "{}_".format(startswith) + str(
        int(re.search(r'\d+(?=\.)', files[-1]).group(0)) + 1 if files else 1) + extension


class FileAction:

    def __init__(self, filename):
        self.filename = filename

    def add_line(self, line, prepend=False):
        logger.info("Appending into file {}".format(self.filename))
        with open(self.filename, 'r+') as f:
            content = f.read()
            if prepend:
                f.seek(0, 0)
                f.write("".join(line) + content)
            else:
                f.write("".join(line))
            f.close()

    def edit_sql(self):
        logger.info("editing ALTER into file {}".format(self.filename))
        with open(self.filename, "r") as f:
            lines = f.readlines()
        with open(self.filename, "w") as f:
            for line in lines:
                if "ALTER" not in line:
                    f.write(line)
        f.close()

    def write_data(self, data):
        logger.info("Writing into file {}".format(self.filename))
        with open(self.filename, "w") as f:
            f.write(data)
        f.close()
        logger.info("Write into file {}".format(self.filename))


class DatabasePassword:

    def __init__(self, server, db_user, server_type=None):
        self.server = server
        self.db_user = db_user
        self.server_type = [server_type] if server_type else ["staging", "production"]
        self.output = None

    def response(self, message):
        logger.info(message)
        self.output = message

    def login(self):
        url = VAULT_URL.rstrip("/") + "/v1/auth/userpass/login/" + VALUT_USER
        data = {
            "password": VAULT_PASSWORD
        }

        logger.info("logging in into vault")
        try:
            output = requests.post(url, data, verify=False)
            self.output = json.loads(output.content.decode())
            if output.status_code == 200:
                return True
            return False
        except Exception as e:
            self.response("Error while logging in into vault : {}".format(str(e)))
            return False

    def read_data_from_vault(self, server_type, client_token):
        url = VAULT_URL.rstrip("/") + "/v1/kv/data/{}/{}/{}/{}".format(VAULT_PATH, server_type, self.server,
                                                                       self.db_user)
        headers = {
            "X-Vault-Token": client_token
        }

        logger.info("getting data from vault")
        try:
            output = requests.get(url, headers=headers, verify=False)
            self.output = json.loads(output.content.decode())
            if output.status_code == 200:
                return True
            elif output.status_code == 404:
                self.response(
                    "Password not present on vault for server {} and user {}".format(self.server, self.db_user))
                return False
            return False
        except Exception as e:
            self.response("Error while getting data from vault : {}".format(str(e)))
            return False

    def get_password(self):
        if self.login():
            client_token = self.output["auth"]["client_token"]
            for server in self.server_type:
                if self.read_data_from_vault(server, client_token):
                    try:
                        password = self.output["data"]["data"]["{}".format(self.db_user)]
                        return True, password
                    except Exception as e:
                        print(str(e))
                        self.response("password not available for user : {}".format(self.db_user))
                        break

            return False, self.output
        else:
            return False, self.output


class SshUtil:
    """Class to connect to remote server"""

    def __init__(self, service):

        self.ssh_output = ""
        self.ssh_error = None
        self.client = None
        self.sftp = None
        self.conn = None
        self.service = service
        self.source = service.source_server
        self.destination = service.destination_server
        self.source_database = service.source_database
        self.destination_database = service.destination_database
        self.source_client = None
        self.destination_client = None
        self.source_database_password = None
        self.dest_database_password = None

    def close_connections(self):
        """
        Function to close all connection if alive.

        :return: None
        """
        with contextlib.suppress(pymysql.err.Error, AttributeError):
            self.client.close()
            self.conn.close()
            self.sftp.close()
            self.source_client.close()
            self.destination_client.close()

    def get_cmd(self, server, query):
        if server is dds:
            return mysql_conn.format(self.destination_database.db_user, self.dest_database_password,
                                     self.destination_database.host).split(" ") + query
        else:
            return mysql_conn.format(self.source_database.db_user, self.source_database_password,
                                     self.source_database.host).split(" ") + query

    def err(self, message):
        """
        It will log the error and assign it to self.err and will close all connections if alive.
        It will also raise exception to stop all executions.

        :param str message: error message to log.
        :return: None
        :raise: exception.
        """
        logger.error(message)
        self.ssh_error = message
        self.close_connections()
        raise

    def response(self, message):
        logger.info(message)
        self.ssh_output = message

    def get_vault_password(self, database_server):
        try:
            if database_server.key:
                server_type = "staging" if "stagging" in database_server.key.name else "production"
            else:
                server_type = None
            password_obj = DatabasePassword(database_server.host, database_server.db_user, server_type)
            result_flag, self.ssh_output = password_obj.get_password()

            if not result_flag:
                raise Exception(self.ssh_output)
            return self.ssh_output

        except Exception as e:
            self.err(str(e))

    def connect_server(self, server, name):
        """Login to the remote server"""
        try:

            # Paramiko.SSHClient can be used to make connections to the remote server and transfer files
            logger.info("Establishing ssh connection with {}".format(name))
            self.client = paramiko.SSHClient()
            # Parsing an instance of the AutoAddPolicy to set_missing_host_key_policy() changes it to allow any host.
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Connect to the server
            if not server.password:
                pkey = paramiko.RSAKey.from_private_key_file(MEDIA_ROOT + server.key.name)
                self.client.connect(hostname=server.host, port=server.port,
                                    username=server.username, pkey=pkey, timeout=float(server.timeout),
                                    allow_agent=False, look_for_keys=False, banner_timeout=200)
                logger.info("Connected to the {} {}".format(name, server.host))
            else:

                self.client.connect(hostname=server.host, port=server.port,
                                    username=server.username, password=server.password,
                                    timeout=float(server.timeout), allow_agent=False, look_for_keys=False)
                logger.info("Connected to the {} {}".format(name, server.host))

            return self.client

        except paramiko.AuthenticationException:
            self.err("Authentication failed, please verify your credentials of {}".format(name))

        except paramiko.SSHException as sshException:
            self.err("Could not establish SSH connection with {}: {}".format(name, sshException))

        except socket.timeout as e:
            self.err("Connection timed out with {}: {}".format(name, e))

        except Exception as e:
            self.err('Exception in connecting to the {}: {}'.format(name, e))

    def execute_command(self, command, input_file=None):

        try:
            logger.info("Executing command --> {}".format(command))
            try:
                if input_file:
                    file_obj = open(input_file, "rb")
                    output = subprocess.check_output(command, stderr=subprocess.PIPE, input=file_obj.read())
                else:
                    output = subprocess.check_output(command, stderr=subprocess.PIPE)
                self.ssh_output = output.decode(sys.getfilesystemencoding())
            except subprocess.CalledProcessError as exc:
                self.ssh_error = exc.output.decode(sys.getfilesystemencoding())
                raise Exception("Problem while running command: {} on local :{}".format(command, self.ssh_error))

            logger.info("Command execution completed successfully on local: {}".format(command))

            return self.ssh_output

        except Exception as e:
            self.err(str(e))

    def delete_data(self, files, path, name, startswith):

        try:
            names = get_file_name(startswith, files, names=True)

            if len(names) >= 5:
                if name == "local":
                    os.remove(path + names[0])
                else:
                    self.sftp_command(self.destination_client, path + "/" + names[0], 'rmfile', name)

        except Exception as e:
            self.err("Error while removing file from {} -> {}".format(name, str(e)))

    def backup_data(self, files, startswith, extension, **kwargs):
        """
        Delete old file if delete=True and create new file if delete=False.

        :param str files: files already present in backup folder
        :param str extension: extension of the backup file
        :param str startswith: filter files with start words
        :return: None
        """

        try:
            file_name = get_file_name(startswith, files, extension)

            bkp_folder = kwargs["bkp_folder"]

            with tarfile.open(media_path + file_name, "w:gz") as tar:
                tar.add(bkp_folder, arcname='.')

            return file_name

        except Exception as e:
            self.err("Error in backup file: {}".format(str(e)))

    def sftp_command(self, client, path, action, name):
        try:
            self.sftp = client.open_sftp()
            switcher = {
                "listdir": lambda: self.sftp.listdir(path),
                "rmfile": lambda: self.sftp.remove(path),
            }

            output = switcher.get(action)()
            return output

        except Exception as e:
            return self.err("Error while running {} for path {} on {}: {}".format(action, path, name, str(e)))

    def sftp_data(self, source, destination, client, name, file=False, put=False):
        """
        Copy files or folder from source to destination.

        :param str source: path on source server.
        :param str destination: path on destination server.
        :param obj client: server object.
        :param str name: type of server (source or destination).
        :param bool file: if data in file or folder
        :param bool put: if we want to put or get file or folder
        :return: None
        :raises: exception
        """

        try:
            self.sftp = client.open_sftp()

            if not put:
                for item in self.sftp.listdir(source):
                    remotepath = source + "/" + item
                    localpath = os.path.join(destination, item)
                    mode = self.sftp.stat(remotepath).st_mode
                    if S_ISDIR(mode):
                        with contextlib.suppress(OSError):
                            os.makedirs(localpath, exist_ok=True)
                        self.sftp_data(remotepath, localpath, client, name)
                    elif S_ISREG(mode):
                        self.sftp.get(remotepath, localpath)

            else:
                if not file:
                    for item in os.listdir(source):
                        remotepath = destination + "/" + item
                        localpath = os.path.join(source, item)
                        mode = os.stat(localpath).st_mode
                        if S_ISDIR(mode):
                            with contextlib.suppress(OSError):
                                self.sftp.mkdir(remotepath)
                            self.sftp_data(localpath, remotepath, client, name, put=True)
                        elif S_ISREG(mode):
                            self.sftp.put(localpath, remotepath)

                else:
                    self.sftp.put(source, destination)

        except Exception as e:
            return self.err("Error while copying data to {}: {}".format(name, str(e)))

    def transfer_assets(self):
        try:
            if "{{hotel_id}}" in self.service.source_path.path_for_assets:

                # Connect servers
                self.source_client = self.connect_server(self.source, ss)
                self.destination_client = self.connect_server(self.destination, ds)
                if self.source_database.db_password:
                    self.source_database_password = self.source_database.db_password
                else:
                    self.source_database_password = self.get_vault_password(self.source_database)

                if self.destination_database.db_password:
                    self.dest_database_password = self.destination_database.db_password
                else:
                    self.dest_database_password = self.get_vault_password(self.destination_database)

                # Get source hotel ID
                command = mysql_conn.format(self.source_database.db_user, self.source_database_password,
                                            self.source_database.host).split(" ") + hotel_query

                source_hotel_id = get_hotel(self.execute_command(command))

                # Get destination hotel ID
                command = mysql_conn.format(self.destination_database.db_user, self.dest_database_password,
                                            self.destination_database.host).split(" ") + hotel_query

                destination_hotel_id = get_hotel(self.execute_command(command))

                # Path of assets on source and destination server
                path_for_assets = self.service.source_path.path_for_assets
                source_asset_path = get_path(path_for_assets, "/" + source_hotel_id)
                destination_asset_path = get_path(path_for_assets, "/" + destination_hotel_id)

                source_data = local_copy_path.format(self.source.id)
                destination_data: str = local_copy_path.format(self.destination.id)

                # Make local directory if not available
                with contextlib.suppress(FileExistsError):
                    os.makedirs(source_data, exist_ok=True)
                    os.makedirs(destination_data, exist_ok=True)
                    logger.info("local path created")

                # Make Backup
                if self.service.make_backup:
                    path = get_path(path_for_assets, "")

                    # present file names
                    present_files = self.sftp_command(self.destination_client, path, 'listdir', ds)

                    # delete already backup file
                    self.delete_data(present_files, path, ds, "bkp")

                    # From destination server to local
                    self.sftp_data(destination_asset_path, destination_data, self.destination_client, ds)

                    # make tar file
                    file_name = self.backup_data(present_files, "bkp", tar_ext, bkp_folder=destination_data)

                    # sftp tar file to destination server
                    self.sftp_data(media_path + file_name, path + "/" + file_name, self.destination_client, ds,
                                   file=True, put=True)

                # From source server to local
                self.sftp_data(source_asset_path, source_data, self.source_client, ss)

                # From local to destination server
                self.sftp_data(source_data.rstrip("/"), destination_asset_path, self.destination_client, ds, put=True)

                # save and log success
                self.response("Assets Copied")

            else:
                self.ssh_output = "Not implemented yet"

            # Close all connections
            self.close_connections()

            # Remove folder from local
            with contextlib.suppress(FileNotFoundError, UnboundLocalError):
                shutil.rmtree(source_data.rstrip("/"))
                shutil.rmtree(destination_data.rstrip("/"))
                os.remove(media_path + file_name)

            return True, self.ssh_output

        except Exception as e:
            with contextlib.suppress(FileNotFoundError, UnboundLocalError):
                shutil.rmtree(source_data.rstrip("/"))
                shutil.rmtree(destination_data.rstrip("/"))
                os.remove(media_path + file_name)
            if self.ssh_error:
                return False, self.ssh_error
            return False, "Error: {}".format(str(e))

    def transfer_database(self):

        try:
            if self.source_database.db_password:
                self.source_database_password = self.source_database.db_password
            else:
                self.source_database_password = self.get_vault_password(self.source_database)

            if self.destination_database.db_password:
                self.dest_database_password = self.destination_database.db_password
            else:
                self.dest_database_password = self.get_vault_password(self.destination_database)

            # Get tables names
            connection = mysql_conn.format(self.source_database.db_user, self.source_database_password,
                                           self.source_database.host).split(" ")
            hotel_table_query = ["-e", get_tables_name.format(self.service.source_path.model_for_database)]
            tables_list = self.execute_command(connection + hotel_table_query).split("\n")[1].split(",")
            tables_list.remove(self.service.source_path.model_for_database + "_configs")

            # Get destination hotel ID and name
            command = self.get_cmd(dds, hotel_query)
            destination_hotel_id, destination_hotel_code = get_hotel(self.execute_command(command), code=True)

            # define local variable
            sql_file = "cloud_{}".format(self.service.destination_path.model_for_database)
            sql_bkp_file = "cloud_{}_bkp".format(self.service.destination_path.model_for_database)
            source_data_file = local_copy_path.format(sql_file + sql_ext).rstrip("/")

            folder_name = destination_hotel_code + "-" + ("staging" if "stagging" in self.destination_database.key.name
                                                          else "production")
            logger.info("Backup Folder -> {}".format(folder_name))
            dest_bkp_path = bkp_path.format(folder_name)
            source_bkp_path = source_path.format(folder_name)

            # make path and remove file
            with contextlib.suppress(FileNotFoundError, FileExistsError):
                os.mkdir(media_path)
                os.remove(source_data_file)
            os.makedirs(source_bkp_path, exist_ok=True)
            os.makedirs(dest_bkp_path, exist_ok=True)

            # get mysql dump from source server
            source_backup = self.execute_command(
                mysqldump.format(self.source_database.db_user, self.source_database_password,
                                 self.source_database.host, " ".join(tables_list)).split(" "))

            # edit .sql file
            append = ["\nset sql_safe_updates=0;"]
            prepend = ["use digivalet_cloud; \n"]

            for table_name in tables_list:
                prepend.append("truncate table {}; \n".format(table_name))
                # noinspection SqlResolve
                append.append("\nupdate {} set hotel_id={};".format(table_name, destination_hotel_id))

            # Action of sql file
            file_action_obj = FileAction(source_data_file)
            file_action_obj.write_data(source_backup)
            file_action_obj.add_line(prepend, prepend=True)
            file_action_obj.add_line(append)
            file_action_obj.edit_sql()

            # Make backup
            if self.service.make_backup:
                destination_backup = self.execute_command(
                    mysqldump.format(self.destination_database.db_user, self.dest_database_password,
                                     self.destination_database.host,
                                     " ".join(tables_list)).split(" "))

                # present file names
                present_files = os.listdir(dest_bkp_path)

                # delete already backup file
                self.delete_data(present_files, dest_bkp_path, "local", sql_bkp_file)

                file_action_obj = FileAction(dest_bkp_path + get_file_name(sql_bkp_file, present_files, sql_ext))
                file_action_obj.write_data(destination_backup)

            # present file names
            present_files = os.listdir(source_bkp_path)

            # delete already backup file
            self.delete_data(present_files, source_bkp_path, "local", sql_bkp_file)

            file_action_obj = FileAction(source_bkp_path + get_file_name(sql_bkp_file, present_files, sql_ext))
            file_action_obj.write_data(source_backup)

            # restore file
            self.execute_command(restore_database.format(self.destination_database.db_user, self.dest_database_password,
                                                         self.destination_database.host).split(" "),
                                 input_file=source_data_file)

            # For restaurant module only
            if "restaurant" in self.service.destination_path.name:

                # get data to replace in update query
                source_hotel_id = get_hotel(self.execute_command(self.get_cmd(sds, hotel_query)))
                destination_his_url = get_his_url(self.execute_command(self.get_cmd(dds, his_url_cmd)))
                source_his_url = get_his_url(self.execute_command(self.get_cmd(sds, his_url_cmd)))

                # Update his url
                self.execute_command(self.get_cmd(dds, ["-e", update_path.format(source_his_url, destination_his_url)]))

                # Update path
                update_path_query = ["-e", update_path.format(assets_path.format(source_hotel_id),
                                                              assets_path.format(destination_hotel_id))]
                self.execute_command((self.get_cmd(dds, update_path_query)))

            # save and log success
            self.response("Database copied")

            # close all connections
            self.close_connections()

            return True, self.ssh_output

        except Exception as e:
            if self.ssh_error:
                return False, self.ssh_error
            return False, "Error: {}".format(str(e))
