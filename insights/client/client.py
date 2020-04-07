from __future__ import print_function
from __future__ import absolute_import
import sys
import json
import logging
import logging.handlers
import os
import time
import six

from .utilities import (generate_machine_id,
                        write_to_disk,
                        write_registered_file,
                        write_unregistered_file,
                        delete_registered_file,
                        delete_unregistered_file,
                        delete_cache_files,
                        determine_hostname,
                        read_pidfile,
                        systemd_notify)
from .collection_rules import InsightsUploadConf
from .data_collector import DataCollector
from .connection import InsightsConnection
from .archive import InsightsArchive
from .support import registration_check
from .constants import InsightsConstants as constants
from .schedule import get_scheduler


def get_machine_id():
    return generate_machine_id()


def get_branch_info(config):
    """
    Get branch info for a system
    returns (dict): {'remote_branch': -1, 'remote_leaf': -1}
    """
    # in the case we are running on offline mode
    # or we are analyzing a running container/image
    # or tar file, mountpoint, simply return the default branch info
    if config.offline:
        return constants.default_branch_info
    return config.branch_info


def collect(config, pconn):
    """
    All the heavy lifting done here
    """
    branch_info = get_branch_info(config)
    pc = InsightsUploadConf(config)
    output = None

    collection_rules = pc.get_conf_file()
    rm_conf = pc.get_rm_conf()
    if rm_conf:
        logger.warn("WARNING: Excluding data from files")

    # defaults
    mp = None
    archive = InsightsArchive(config)

    msg_name = determine_hostname(config.display_name)
    dc = DataCollector(config, archive, mountpoint=mp)
    logger.info('Starting to collect Insights data for %s', msg_name)
    dc.run_collection(collection_rules, rm_conf, branch_info)
    output = dc.done(collection_rules, rm_conf)
    return output


def get_connection(config):
    return InsightsConnection(config)


def _legacy_upload(config, pconn, tar_file, content_type, collection_duration=None):
    logger.info('Uploading Insights data.')
    api_response = None
    parent_pid = read_pidfile()
    for tries in range(config.retries):
        systemd_notify(parent_pid)
        upload = pconn.upload_archive(tar_file, '', collection_duration)

        if upload.status_code in (200, 201):
            api_response = json.loads(upload.text)

            # Write to last upload file
            with open(constants.last_upload_results_file, 'w') as handler:
                if six.PY3:
                    handler.write(upload.text)
                else:
                    handler.write(upload.text.encode('utf-8'))
            write_to_disk(constants.lastupload_file)

            msg_name = determine_hostname(config.display_name)
            account_number = config.account_number
            if account_number:
                logger.info("Successfully uploaded report from %s to account %s.",
                            msg_name, account_number)
            else:
                logger.info("Successfully uploaded report for %s.", msg_name)
            break

        elif upload.status_code in (412, 413):
            pconn.handle_fail_rcs(upload)
            raise RuntimeError('Upload failed.')
        else:
            logger.error("Upload attempt %d of %d failed! Status Code: %s",
                         tries + 1, config.retries, upload.status_code)
            if tries + 1 != config.retries:
                logger.info("Waiting %d seconds then retrying",
                            constants.sleep_time)
                time.sleep(constants.sleep_time)
            else:
                logger.error("All attempts to upload have failed!")
                logger.error("Please see %s for additional information", config.logging_file)
                raise RuntimeError('Upload failed.')
    return api_response


def upload(config, pconn, tar_file, content_type, collection_duration=None):
    if config.legacy_upload:
        return _legacy_upload(config, pconn, tar_file, content_type, collection_duration)
    logger.info('Uploading Insights data.')
    parent_pid = read_pidfile()
    for tries in range(config.retries):
        systemd_notify(parent_pid)
        upload = pconn.upload_archive(tar_file, content_type, collection_duration)

        if upload.status_code in (200, 202):
            msg_name = determine_hostname(config.display_name)
            logger.info("Successfully uploaded report for %s.", msg_name)
            return
        elif upload.status_code in (413, 415):
            pconn.handle_fail_rcs(upload)
            raise RuntimeError('Upload failed.')
        else:
            logger.error("Upload attempt %d of %d failed! Status code: %s",
                         tries + 1, config.retries, upload.status_code)
            if tries + 1 != config.retries:
                logger.info("Waiting %d seconds then retrying",
                            constants.sleep_time)
                time.sleep(constants.sleep_time)
            else:
                logger.error("All attempts to upload have failed!")
                logger.error("Please see %s for additional information", config.logging_file)
                raise RuntimeError('Upload failed.')
