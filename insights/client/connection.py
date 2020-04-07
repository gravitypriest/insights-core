"""
Module handling HTTP Requests and Connection Diagnostics
"""
from __future__ import print_function
from __future__ import absolute_import
import requests
import os
import six
import json
import logging
import pkg_resources
import platform
import xml.etree.ElementTree as ET
import warnings
# import io
from tempfile import TemporaryFile
# from datetime import datetime, timedelta
try:
    # python 2
    from urlparse import urlparse
    from urllib import quote
except ImportError:
    # python 3
    from urllib.parse import urlparse
    from urllib.parse import quote
from .cert_auth import rhsmCertificate
from .constants import InsightsConstants as constants
from .url_cache import URLCache
from insights import package_info
from insights.core.context import Context
from insights.parsers.os_release import OsRelease
from insights.parsers.redhat_release import RedhatRelease

warnings.simplefilter('ignore')
APP_NAME = constants.app_name
NETWORK = constants.custom_network_log_level
logger = logging.getLogger(__name__)

"""
urllib3's logging is chatty
"""
URLLIB3_LOGGER = logging.getLogger('urllib3.connectionpool')
URLLIB3_LOGGER.setLevel(logging.WARNING)
URLLIB3_LOGGER = logging.getLogger('requests.packages.urllib3.connectionpool')
URLLIB3_LOGGER.setLevel(logging.WARNING)

# TODO: Document this, or turn it into a real option
if os.environ.get('INSIGHTS_DEBUG_HTTP'):
    import httplib
    httplib.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


class UploadTooLargeError(Exception):
    '''
    Raised when the API responds with a 413 status
    '''
    pass


class InvalidContentTypeError(Exception):
    '''
    Raised when the API responds with a 415 status
    '''
    pass


class InsightsConnection(object):

    """
    Handle network setup and requests
    """

    def __init__(self, config):
        self.config = config
        self.username = self.config.username
        self.password = self.config.password

        # workaround while we support both legacy and plat APIs
        self.cert_verify = self.config.cert_verify
        if self.cert_verify is None:
            # if self.config.legacy_upload:
            self.cert_verify = os.path.join(
                constants.default_conf_dir,
                'cert-api.access.redhat.com.pem')
            # else:
            # self.cert_verify = True
        else:
            if isinstance(self.cert_verify, six.string_types):
                if self.cert_verify.lower() == 'false':
                    self.cert_verify = False
                elif self.cert_verify.lower() == 'true':
                    self.cert_verify = True

        protocol = "https://"
        insecure_connection = self.config.insecure_connection
        if insecure_connection:
            # This really should not be used.
            protocol = "http://"
            self.cert_verify = False

        self.auto_config = self.config.auto_config

        # workaround while we support both legacy and plat APIs
        # hack to "guess" the correct base URL if autoconfig off +
        #   no base_url in config
        if self.config.base_url is None:
            if self.config.legacy_upload:
                self.base_url = protocol + constants.legacy_base_url
            else:
                self.base_url = protocol + constants.base_url
        else:
            self.base_url = protocol + self.config.base_url
        # end hack. in the future, make cloud.redhat.com the default

        self.upload_url = self.config.upload_url
        if self.upload_url is None:
            if self.config.legacy_upload:
                self.upload_url = self.base_url + "/uploads"
            else:
                self.upload_url = self.base_url + '/ingress/v1/upload'

        self.api_url = self.base_url
        self.branch_info_url = self.config.branch_info_url
        if self.branch_info_url is None:
            # workaround for a workaround for a workaround
            base_url_base = self.base_url.split('/platform')[0]
            self.branch_info_url = base_url_base + '/v1/branch_info'
        self.authmethod = self.config.authmethod
        self.systemid = self.config.systemid or None
        self.get_proxies()
        self.session = self._init_session()

    @property
    def user_agent(self):
        """
        Generates and returns a string suitable for use as a request user-agent
        """
        core_version = "insights-core"
        pkg = pkg_resources.working_set.find(pkg_resources.Requirement.parse(core_version))
        if pkg is not None:
            core_version = "%s %s" % (pkg.project_name, pkg.version)
        else:
            core_version = "Core %s" % package_info["VERSION"]

        client_version = "insights-client"
        pkg = pkg_resources.working_set.find(pkg_resources.Requirement.parse(client_version))
        if pkg is not None:
            client_version = "%s/%s" % (pkg.project_name, pkg.version)

        requests_version = None
        pkg = pkg_resources.working_set.find(pkg_resources.Requirement.parse("requests"))
        if pkg is not None:
            requests_version = "%s %s" % (pkg.project_name, pkg.version)

        python_version = "%s %s" % (platform.python_implementation(), platform.python_version())

        os_family = "Unknown"
        os_release = ""
        for p in ["/etc/os-release", "/etc/redhat-release"]:
            try:
                with open(p) as f:
                    data = f.readlines()

                ctx = Context(content=data, path=p, relative_path=p)
                if p == "/etc/os-release":
                    rls = OsRelease(ctx)
                    os_family = rls.data.get("NAME")
                    os_release = rls.data.get("VERSION_ID")
                elif p == "/etc/redhat-release":
                    rls = RedhatRelease(ctx)
                    os_family = rls.product
                    os_release = rls.version
                break
            except IOError:
                continue
            except Exception as e:
                logger.warning("Failed to detect OS version: %s", e)
        kernel_version = "%s %s" % (platform.system(), platform.release())

        ua = "{client_version} ({core_version}; {requests_version}) {os_family} {os_release} ({python_version}; {kernel_version})".format(
            client_version=client_version,
            core_version=core_version,
            python_version=python_version,
            os_family=os_family,
            os_release=os_release,
            kernel_version=kernel_version,
            requests_version=requests_version,
        )

        return ua

    def _init_session(self):
        """
        Set up the session, auth is handled here
        """
        session = requests.Session()
        session.headers = {'User-Agent': self.user_agent,
                           'Accept': 'application/json'}
        if self.systemid is not None:
            session.headers.update({'systemid': self.systemid})
        if self.authmethod == "BASIC":
            session.auth = (self.username, self.password)
        elif self.authmethod == "CERT":
            cert = rhsmCertificate.certpath()
            key = rhsmCertificate.keypath()
            if rhsmCertificate.exists():
                session.cert = (cert, key)
            else:
                logger.error('ERROR: Certificates not found.')
        session.verify = self.cert_verify
        session.proxies = self.proxies
        session.trust_env = False
        if self.proxy_auth:
            # HACKY
            try:
                # Need to make a request that will fail to get proxies set up
                logger.log(NETWORK, "GET %s", self.base_url)
                session.request(
                    "GET", self.base_url, timeout=self.config.http_timeout)
            except requests.ConnectionError:
                pass
            # Major hack, requests/urllib3 does not make access to
            # proxy_headers easy
            proxy_mgr = session.adapters['https://'].proxy_manager[self.proxies['https']]
            auth_map = {'Proxy-Authorization': self.proxy_auth}
            proxy_mgr.proxy_headers = auth_map
            proxy_mgr.connection_pool_kw['_proxy_headers'] = auth_map
            conns = proxy_mgr.pools._container
            for conn in conns:
                connection = conns[conn]
                connection.proxy_headers = auth_map
        return session

    def _http_request(self, req, url, method, qp=None, headers=None, data=None, files=None):
        '''
        Perform an HTTP request, net logging, and error handling

        Parameters
            req     - request callback from the session object, e.g. session.get
            url     - URL to perform the request against
            method  - HTTP request method, e.g. GET
            qp      - HTTP query parameters
            headers - HTTP headers
            data    - POST data to send
            files   - POST files to send
        Returns
            HTTP response object on success
            None on failure
        '''
        try:
            logger.log(NETWORK, "%s %s", method, url)
            res = req(url, timeout=self.config.http_timeout, files=files)
            logger.log(NETWORK, "HTTP Status Code: %d", res.status_code)
            logger.log(NETWORK, "HTTP Status Text: %s", res.reason)
            logger.log(NETWORK, "HTTP Response Text: %s", res.text)
            res.raise_for_status()
            return res
        except requests.Timeout as e:
            logger.error(e)
            logger.error('Connection timed out.')
            return None
        except requests.ConnectionError as e:
            logger.error(e)
            logger.error('The Insights API could not be reached.')
            return None
        except requests.exceptions.HTTPError as e:
            logger.error(e)
            self.handle_fail_rcs(res)
            return None

    def get(self, url, qp=None, headers=None):
        return self._http_request(self.session.get, url, 'GET', qp=qp, headers=headers)

    def post(self, url, qp=None, headers=None, data=None, files=None):
        return self._http_request(self.session.post, url, 'POST', qp=qp, headers=headers, data=data, files=files)

    def put(self, url, qp=None, headers=None, data=None, files=None):
        return self._http_request(self.session.put, url, 'PUT', qp=qp, headers=headers, data=data, files=files)

    def delete(self, url, qp=None, headers=None):
        return self._http_request(self.session.delete, url, 'DELETE', qp=qp, headers=headers)

    def get_proxies(self):
        """
        Determine proxy configuration
        """
        # Get proxy from ENV or Config
        proxies = None
        proxy_auth = None
        no_proxy = os.environ.get('NO_PROXY')
        logger.debug("NO PROXY: %s", no_proxy)

        # CONF PROXY TAKES PRECEDENCE OVER ENV PROXY
        conf_proxy = self.config.proxy
        if ((conf_proxy is not None and
             conf_proxy.lower() != 'None'.lower() and
             conf_proxy != "")):
            if '@' in conf_proxy:
                scheme = conf_proxy.split(':')[0] + '://'
                logger.debug("Proxy Scheme: %s", scheme)
                location = conf_proxy.split('@')[1]
                logger.debug("Proxy Location: %s", location)
                username = conf_proxy.split(
                    '@')[0].split(':')[1].replace('/', '')
                logger.debug("Proxy User: %s", username)
                password = conf_proxy.split('@')[0].split(':')[2]
                proxy_auth = requests.auth._basic_auth_str(username, password)
                conf_proxy = scheme + location
            logger.debug("CONF Proxy: %s", conf_proxy)
            proxies = {"https": conf_proxy}

        # HANDLE NO PROXY CONF PROXY EXCEPTION VERBIAGE
        if no_proxy and conf_proxy:
            logger.debug("You have environment variable NO_PROXY set "
                         "as well as 'proxy' set in your configuration file. "
                         "NO_PROXY environment variable will be ignored.")

        # IF NO CONF PROXY, GET ENV PROXY AND NO PROXY
        if proxies is None:
            env_proxy = os.environ.get('HTTPS_PROXY')
            if env_proxy:
                if '@' in env_proxy:
                    scheme = env_proxy.split(':')[0] + '://'
                    logger.debug("Proxy Scheme: %s", scheme)
                    location = env_proxy.split('@')[1]
                    logger.debug("Proxy Location: %s", location)
                    username = env_proxy.split('@')[0].split(':')[1].replace('/', '')
                    logger.debug("Proxy User: %s", username)
                    password = env_proxy.split('@')[0].split(':')[2]
                    proxy_auth = requests.auth._basic_auth_str(username, password)
                    env_proxy = scheme + location
                logger.debug("ENV Proxy: %s", env_proxy)
                proxies = {"https": env_proxy}
            if no_proxy:
                insights_service_host = urlparse(self.base_url).hostname
                logger.debug('Found NO_PROXY set. Checking NO_PROXY %s against base URL %s.', no_proxy, insights_service_host)
                for no_proxy_host in no_proxy.split(','):
                    logger.debug('Checking %s against %s', no_proxy_host, insights_service_host)
                    if no_proxy_host == '*':
                        proxies = None
                        proxy_auth = None
                        logger.debug('Found NO_PROXY asterisk(*) wildcard, disabling all proxies.')
                        break
                    elif no_proxy_host.startswith('.') or no_proxy_host.startswith('*'):
                        if insights_service_host.endswith(no_proxy_host.replace('*', '')):
                            proxies = None
                            proxy_auth = None
                            logger.debug('Found NO_PROXY range %s matching %s', no_proxy_host, insights_service_host)
                            break
                    elif no_proxy_host == insights_service_host:
                        proxies = None
                        proxy_auth = None
                        logger.debug('Found NO_PROXY %s exactly matching %s', no_proxy_host, insights_service_host)
                        break

        self.proxies = proxies
        self.proxy_auth = proxy_auth

    def _test_urls(self, url, method):
        '''
        Test a URL
        '''
        logger.debug('Testing %s', url)
        if method is 'POST':
            test_tar = TemporaryFile(mode='rb', suffix='.tar.gz')
            test_files = {
                'file': ('test.tar.gz', test_tar, constants.default_content_type),
                'metadata': '{\"test\": \"test\"}'
            }
            test_req = self.post(url, files=test_files)
        elif method is "GET":
            test_req = self.get(url)
        if test_req:
            logger.info(
                "Successfully connected to: %s", url)
            return True
        else:
            logger.info("Connection failed")
            return False

    def test_connection(self, rc=0):
        """
        Test connection to Red Hat
        """
        logger.debug("Proxy config: %s", self.proxies)
        try:
            logger.info("=== Begin Upload URL Connection Test ===")
            upload_success = self._test_urls(self.upload_url, "POST")
            logger.info("=== End Upload URL Connection Test: %s ===\n",
                        "SUCCESS" if upload_success else "FAILURE")
            logger.info("=== Begin API URL Connection Test ===")
            if self.config.legacy_upload:
                api_success = self._test_urls(self.base_url, "GET")
            else:
                api_success = self._test_urls(self.base_url + '/apicast-tests/ping', 'GET')
            logger.info("=== End API URL Connection Test: %s ===\n",
                        "SUCCESS" if api_success else "FAILURE")
            if upload_success and api_success:
                logger.info("Connectivity tests completed successfully")
                logger.info("See %s for more details.", self.config.logging_file)
            else:
                logger.info("Connectivity tests completed with some errors")
                logger.info("See %s for more details.", self.config.logging_file)
                rc = 1
        except requests.ConnectionError as exc:
            print(exc)
            logger.error('Connectivity test failed! '
                         'Please check your network configuration')
            logger.error('Additional information may be in'
                         ' /var/log/' + APP_NAME + "/" + APP_NAME + ".log")
            return 1
        return rc

    def handle_fail_rcs(self, req):
        """
        Handle HTTP failure codes excepted
        by raise_for_status()
        """
        # attempt to read the HTTP response JSON message
        try:
            logger.log(NETWORK, "HTTP Response Message: %s", req.json()["message"])
        except:
            logger.debug("No HTTP Response message present.")

        # handle specific status codes
        logger.debug("Debug Information:\nHTTP Status Code: %s",
                    req.status_code)
        logger.debug("HTTP Status Text: %s", req.reason)
        if req.status_code == 401:
            logger.error("Authorization Required.")
            logger.error("Please ensure correct credentials "
                         "in " + constants.default_conf_file)
            logger.log(NETWORK, "HTTP Response Text: %s", req.text)
        if req.status_code == 402:
            # failed registration because of entitlement limit hit
            logger.debug('Registration failed by 402 error.')
            try:
                logger.error(req.json()["message"])
            except:
                logger.error("Got 402 but no message")
                logger.log(NETWORK, "HTTP Response Text: %s", req.text)
        if req.status_code == 403 and self.auto_config:
            # Insights disabled in satellite
            rhsm_hostname = urlparse(self.base_url).hostname
            if (rhsm_hostname != 'subscription.rhn.redhat.com' and
               rhsm_hostname != 'subscription.rhsm.redhat.com'):
                logger.error('Please enable Insights on Satellite server '
                             '%s to continue.', rhsm_hostname)
        if req.status_code == 412:
            try:
                unreg_date = req.json()["unregistered_at"]
                logger.error(req.json()["message"])
                write_unregistered_file(unreg_date)
            except:
                unreg_date = "412, but no unreg_date or message"
                logger.log(NETWORK, "HTTP Response Text: %s", req.text)
        if req.status_code == 413:
            logger.error('Archive is too large to upload.')
            raise UploadTooLargeError
        if req.status_code == 415:
            logger.error('Invalid content-type.')
            raise InvalidContentTypeError

    def get_satellite5_info(self, branch_info):
        """
        Get remote_leaf for Satellite 5 Managed box
        """
        logger.debug(
            "Remote branch not -1 but remote leaf is -1, must be Satellite 5")
        if os.path.isfile('/etc/sysconfig/rhn/systemid'):
            logger.debug("Found systemid file")
            sat5_conf = ET.parse('/etc/sysconfig/rhn/systemid').getroot()
            leaf_id = None
            for member in sat5_conf.getiterator('member'):
                if member.find('name').text == 'system_id':
                    logger.debug("Found member 'system_id'")
                    leaf_id = member.find('value').find(
                        'string').text.split('ID-')[1]
                    logger.debug("Found leaf id: %s", leaf_id)
                    branch_info['remote_leaf'] = leaf_id
            if leaf_id is None:
                logger.error("Could not determine leaf_id!  Exiting!")
                return False

    def get_branch_info(self):
        """
        Retrieve branch_info from Satellite Server
        """
        # branch_info = None
        # if os.path.exists(constants.cached_branch_info):
        #     # use cached branch info file if less than 5 minutes old
        #     #  (failsafe, should be deleted at end of client run normally)
        #     logger.debug(u'Reading branch info from cached file.')
        #     ctime = datetime.utcfromtimestamp(
        #         os.path.getctime(constants.cached_branch_info))
        #     if datetime.utcnow() < (ctime + timedelta(minutes=5)):
        #         with io.open(constants.cached_branch_info, encoding='utf8', mode='r') as f:
        #             branch_info = json.load(f)
        #         return branch_info
        #     else:
        #         logger.debug(u'Cached branch info is older than 5 minutes.')

        logger.debug(u'Obtaining branch information from %s',
                     self.branch_info_url)
        logger.log(NETWORK, u'GET %s', self.branch_info_url)
        response = self.get(self.branch_info_url)
        logger.log(NETWORK, u'GET branch_info status: %s', response.status_code)
        if response.status_code != 200:
            logger.debug("There was an error obtaining branch information.")
            logger.debug(u'Bad status from server: %s', response.status_code)
            logger.debug("Assuming default branch information %s" % constants.default_branch_info)
            return False

        branch_info = response.json()
        logger.debug(u'Branch information: %s', json.dumps(branch_info))

        # Determine if we are connected to Satellite 5
        if ((branch_info[u'remote_branch'] is not -1 and
             branch_info[u'remote_leaf'] is -1)):
            self.get_satellite5_info(branch_info)

        # logger.debug(u'Saving branch info to file.')
        # with io.open(constants.cached_branch_info, encoding='utf8', mode='w') as f:
        #     # json.dump is broke in py2 so use dumps
        #     bi_str = json.dumps(branch_info, ensure_ascii=False)
        #     f.write(bi_str)
        self.config.branch_info = branch_info
        return branch_info


if __name__ == '__main__':
    from insights.client import InsightsClient
    from insights.client.config import InsightsConfig
    conf = InsightsConfig().load_all()
    InsightsClient(conf)
    c = InsightsConnection(conf)
    c._init_session()
    print(c.get_branch_info())
