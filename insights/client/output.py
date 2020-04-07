import logging
import os
import json
from insights.client.utilities import determine_hostname
from insights.util.canonical_facts import get_canonical_facts
from insights.client.connection import UploadTooLargeError, InvalidContentTypeError
from tempfile import TemporaryFile

logger = logging.getLogger(__name__)


def upload(conn, tar_file, content_type, collection_duration=None):
    '''
    Upload an archive to Insights

    Parameters:
        conn
        tar_file
        content_type
        collection_duration

    Returns

    '''
    logger.info('Uploading Insights data.')
    config = conn.config
    # parent_pid = read_pidfile()
    for tries in range(config.retries):
        # systemd_notify(parent_pid)

        file_name = os.path.basename(tar_file)
        upload_url = conn.upload_url
        c_facts = {}

        try:
            c_facts = get_canonical_facts()
        except Exception as e:
            logger.debug('Error getting canonical facts: %s', e)
        if config.display_name:
            # add display_name to canonical facts
            c_facts['display_name'] = config.display_name
        if config.branch_info:
            c_facts["branch_info"] = config.branch_info
            c_facts["satellite_id"] = config.branch_info["remote_leaf"]
        c_facts = json.dumps(c_facts)
        logger.debug('Canonical facts collected:\n%s', c_facts)

        files = {
            'file': (file_name, open(tar_file, 'rb'), content_type),
            'metadata': c_facts
        }
        logger.debug("Uploading %s to %s", tar_file, upload_url)

        try:
            upload = conn.post(upload_url, files=files, headers={})
        except (UploadTooLargeError, InvalidContentTypeError):
            # do not retry
            raise RuntimeError('Upload failed.')

        if not upload:
            logger.error("Upload attempt %d of %d failed!",
                         tries + 1, config.retries)
            if tries + 1 != config.retries:
                logger.info("Waiting %d seconds then retrying",
                            constants.sleep_time)
                time.sleep(constants.sleep_time)
                continue
            else:
                logger.error("All attempts to upload have failed!")
                logger.error("Please see %s for additional information", config.logging_file)
                raise RuntimeError('Upload failed.')

        logger.debug('Request ID: %s', upload.headers.get('x-rh-insights-request-id', None))
        if upload.status_code in (200, 202):
            # upload = registration on platform
            # write_registered_file()
            msg_name = determine_hostname(config.display_name)
            logger.info("Successfully uploaded report for %s.", msg_name)
        else:
            logger.debug(
                "Upload archive failed with status code %s",
                upload.status_code)
            return upload
        logger.debug("Upload duration: %s", upload.elapsed)


if __name__ == '__main__':
    from insights.client.log import set_up_logging
    from insights.client.config import InsightsConfig
    from insights.client.connection import InsightsConnection
    from insights.client.constants import InsightsConstants as constants
    conf = InsightsConfig(base_url='cert-api.access.redhat.com/r/insights/platform').load_all()
    set_up_logging(conf)
    c = InsightsConnection(conf)
    c._init_session()
    # test_tar = TemporaryFile(mode='rb', suffix='.tar.gz')
    upload(c, 'test.tar.gz', constants.default_content_type)