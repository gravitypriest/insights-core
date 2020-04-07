# -LEGACY-
def create_system(self, new_machine_id=False):
    """
    Create the machine via the API
    """
    client_hostname = determine_hostname()
    machine_id = generate_machine_id(new_machine_id)

    branch_info = self.config.branch_info
    if not branch_info:
        return False

    remote_branch = branch_info['remote_branch']
    remote_leaf = branch_info['remote_leaf']

    data = {'machine_id': machine_id,
            'remote_branch': remote_branch,
            'remote_leaf': remote_leaf,
            'hostname': client_hostname}
    if self.config.display_name is not None:
        data['display_name'] = self.config.display_name
    data = json.dumps(data)
    post_system_url = self.api_url + '/v1/systems'
    return self.post(post_system_url,
                     headers={'Content-Type': 'application/json'},
                     data=data)

# -LEGACY-
def group_systems(self, group_name, systems):
    """
    Adds an array of systems to specified group

    Args:
        group_name: Display name of group
        systems: Array of {'machine_id': machine_id}
    """
    api_group_id = None
    headers = {'Content-Type': 'application/json'}
    group_path = self.api_url + '/v1/groups'
    group_get_path = group_path + ('?display_name=%s' % quote(group_name))

    logger.debug("GET group: %s", group_get_path)
    logger.log(NETWORK, "GET %s", group_get_path)
    get_group = self.session.get(group_get_path)
    logger.debug("GET group status: %s", get_group.status_code)
    if get_group.status_code == 200:
        api_group_id = get_group.json()['id']

    if get_group.status_code == 404:
        # Group does not exist, POST to create
        logger.debug("POST group")
        data = json.dumps({'display_name': group_name})
        logger.log(NETWORK, "POST", group_path)
        post_group = self.session.post(group_path,
                                       headers=headers,
                                       data=data)
        logger.debug("POST group status: %s", post_group.status_code)
        logger.debug("POST Group: %s", post_group.json())
        self.handle_fail_rcs(post_group)
        api_group_id = post_group.json()['id']

    logger.debug("PUT group")
    data = json.dumps(systems)
    logger.log(NETWORK, "PUT %s", group_path + ('/%s/systems' % api_group_id))
    put_group = self.session.put(group_path +
                                 ('/%s/systems' % api_group_id),
                                 headers=headers,
                                 data=data)
    logger.debug("PUT group status: %d", put_group.status_code)
    logger.debug("PUT Group: %s", put_group.json())

# -LEGACY-
# Keeping this function around because it's not private and I don't know if anything else uses it
#
def do_group(self):
    """
    Do grouping on register
    """
    group_id = self.config.group
    systems = {'machine_id': generate_machine_id()}
    self.group_systems(group_id, systems)

# -LEGACY-
#
def _legacy_api_registration_check(self):
    '''
    Check registration status through API
    '''
    logger.debug('Checking registration status...')
    machine_id = generate_machine_id()
    url = self.api_url + '/v1/systems/' + machine_id
    res = self.get(url)
    if not res:
        # can't connect, run connection test
        logger.error('Connection timed out. Running connection test...')
        self.test_connection()
        return False
    # had to do a quick bugfix changing this around,
    #   which makes the None-False-True dichotomy seem weird
    #   TODO: reconsider what gets returned, probably this:
    #       True for registered
    #       False for unregistered
    #       None for system 404
    try:
        # check the 'unregistered_at' key of the response
        unreg_status = json.loads(res.content).get('unregistered_at', 'undefined')
        # set the global account number
        self.config.account_number = json.loads(res.content).get('account_number', 'undefined')
    except ValueError:
        # bad response, no json object
        return False
    if unreg_status == 'undefined':
        # key not found, machine not yet registered
        return None
    elif unreg_status is None:
        # unregistered_at = null, means this machine IS registered
        return True
    else:
        # machine has been unregistered, this is a timestamp
        return unreg_status

#
def _fetch_system_by_machine_id(self):
    '''
    Get a system by machine ID
    Returns
        dict    system exists in inventory
        False   system does not exist in inventory
        None    error connection or parsing response
    '''
    machine_id = generate_machine_id()
    # [circus music]
    if self.config.legacy_upload:
        url = self.base_url + '/platform/inventory/v1/hosts?insights_id=' + machine_id
    else:
        url = self.base_url + '/inventory/v1/hosts?insights_id=' + machine_id
    res = self.get(url)
    if not res:
        return None
    try:
        res_json = json.loads(res.content)
    except ValueError as e:
        logger.error(e)
        logger.error('Could not parse response body.')
        return None
    if res_json['total'] == 0:
        logger.debug('No hosts found with machine ID: %s', machine_id)
        return False
    return res_json['results']

#
def api_registration_check(self):
    '''
        Reach out to the inventory API to check
        whether a machine exists.

        Returns
            True    system exists in inventory
            False   system does not exist in inventory
            None    error connection or parsing response
    '''
    if self.config.legacy_upload:
        return self._legacy_api_registration_check()

    logger.debug('Checking registration status...')
    results = self._fetch_system_by_machine_id()
    if not results:
        return results

    logger.debug('System found.')
    logger.debug('Machine ID: %s', results[0]['insights_id'])
    logger.debug('Inventory ID: %s', results[0]['id'])
    return True

# -LEGACY-
def _legacy_unregister(self):
    """
    Unregister this system from the insights service
    """
    machine_id = generate_machine_id()
    try:
        logger.debug("Unregistering %s", machine_id)
        url = self.api_url + "/v1/systems/" + machine_id
        logger.log(NETWORK, "DELETE %s", url)
        self.session.delete(url)
        logger.info(
            "Successfully unregistered from the Red Hat Insights Service")
        return True
    except requests.ConnectionError as e:
        logger.debug(e)
        logger.error("Could not unregister this system")
        return False

#
def unregister(self):
    """
    Unregister this system from the insights service
    """
    if self.config.legacy_upload:
        return self._legacy_unregister()

    results = self._fetch_system_by_machine_id()
    logger.debug("Unregistering host...")
    url = self.api_url + "/inventory/v1/hosts/" + results[0]['id']
    response = self.delete(url)
    if not response:
        logger.error("Could not unregister this system")
        return False
    logger.info(
        "Successfully unregistered from the Red Hat Insights Service")
    return True

# -LEGACY-
def register(self):
    """
    Register this machine
    """
    client_hostname = determine_hostname()
    # This will undo a blacklist
    logger.debug("API: Create system")
    system = self.create_system(new_machine_id=False)
    if system is False:
        return ('Could not reach the Insights service to register.', '', '', '')

    # If we get a 409, we know we need to generate a new machine-id
    if system.status_code == 409:
        system = self.create_system(new_machine_id=True)
    self.handle_fail_rcs(system)

    logger.debug("System: %s", system.json())

    message = system.headers.get("x-rh-message", "")

    # Do grouping
    if self.config.group is not None:
        self.do_group()

    # Display registration success messasge to STDOUT and logs
    if system.status_code == 201:
        try:
            system_json = system.json()
            machine_id = system_json["machine_id"]
            account_number = system_json["account_number"]
            logger.info("You successfully registered %s to account %s." % (machine_id, account_number))
        except:
            logger.debug('Received invalid JSON on system registration.')
            logger.debug('API still indicates valid registration with 201 status code.')
            logger.debug(system)
            logger.debug(system.json())

    if self.config.group is not None:
        return (message, client_hostname, self.config.group, self.config.display_name)
    elif self.config.display_name is not None:
        return (message, client_hostname, "None", self.config.display_name)
    else:
        return (message, client_hostname, "None", "")

# -LEGACY-
def _legacy_set_display_name(self, display_name):
    machine_id = generate_machine_id()
    try:
        url = self.api_url + '/v1/systems/' + machine_id

        logger.log(NETWORK, "GET %s", url)
        res = self.session.get(url, timeout=self.config.http_timeout)
        old_display_name = json.loads(res.content).get('display_name', None)
        if display_name == old_display_name:
            logger.debug('Display name unchanged: %s', old_display_name)
            return True

        logger.log(NETWORK, "PUT %s", url)
        res = self.session.put(url,
                               timeout=self.config.http_timeout,
                               headers={'Content-Type': 'application/json'},
                               data=json.dumps(
                                    {'display_name': display_name}))
        if res.status_code == 200:
            logger.info('System display name changed from %s to %s',
                        old_display_name,
                        display_name)
            return True
        elif res.status_code == 404:
            logger.error('System not found. '
                         'Please run insights-client --register.')
            return False
        else:
            logger.error('Unable to set display name: %s %s',
                         res.status_code, res.text)
            return False
    except (requests.ConnectionError, requests.Timeout, ValueError) as e:
        logger.error(e)
        # can't connect, run connection test
        return False

def set_display_name(self, display_name):
    '''
    Set display name of a system independently of upload.
    '''
    if self.config.legacy_upload:
        return self._legacy_set_display_name(display_name)

    system = self._fetch_system_by_machine_id()
    if not system:
        return system
    inventory_id = system[0]['id']

    req_url = self.base_url + '/inventory/v1/hosts/' + inventory_id
    try:
        logger.log(NETWORK, "PATCH %s", req_url)
        res = self.session.patch(req_url, json={'display_name': display_name})
    except (requests.ConnectionError, requests.Timeout) as e:
        logger.error(e)
        logger.error('The Insights API could not be reached.')
        return False
    if (self.handle_fail_rcs(res)):
        logger.error('Could not update display name.')
        return False
    logger.info('Display name updated to ' + display_name + '.')
    return True

def get_diagnosis(self, remediation_id=None):
    '''
        Reach out to the platform and fetch a diagnosis.
        Spirtual successor to --to-json from the old client.
    '''
    # this uses machine id as identifier instead of inventory id
    diag_url = self.base_url + '/remediations/v1/diagnosis/' + generate_machine_id()
    params = {}
    if remediation_id:
        # validate this?
        params['remediation'] = remediation_id
    try:
        logger.log(NETWORK, "GET %s", diag_url)
        res = self.session.get(diag_url, params=params, timeout=self.config.http_timeout)
    except (requests.ConnectionError, requests.Timeout) as e:
        logger.error(e)
        logger.error('The Insights API could not be reached.')
        return False
    if (self.handle_fail_rcs(res)):
        logger.error('Unable to get diagnosis data: %s %s',
                     res.status_code, res.text)
        return None
    return res.json()

def _get(self, url):
    '''
        Submits a GET request to @url, caching the result, and returning
        the response body, if any. It makes the response status code opaque
        to the caller.

        Returns: bytes
    '''
    cache = URLCache("/var/cache/insights/cache.dat")

    headers = {}
    item = cache.get(url)
    if item is not None:
        headers["If-None-Match"] = item.etag

    logger.log(NETWORK, "GET %s", url)
    res = self.session.get(url, headers=headers)

    if res.status_code in [requests.codes.OK, requests.codes.NOT_MODIFIED]:
        if res.status_code == requests.codes.OK:
            if "ETag" in res.headers and len(res.content) > 0:
                cache.set(url, res.headers["ETag"], res.content)
                cache.save()
        item = cache.get(url)
        if item is None:
            return res.content
        else:
            return item.content
    else:
        return None

def get_advisor_report(self):
    '''
        Retrieve advisor report
    '''
    url = self.base_url + "/inventory/v1/hosts?insights_id=%s" % generate_machine_id()
    content = self._get(url)
    if content is None:
        return None

    host_details = json.loads(content)
    if host_details["total"] < 1:
        raise Exception("Error: failed to find host with matching machine-id. Run insights-client --status to check registration status")
    if host_details["total"] > 1:
        raise Exception("Error: multiple hosts detected (insights_id = %s)" % generate_machine_id())

    if not os.path.exists("/var/lib/insights"):
        os.makedirs("/var/lib/insights", mode=0o755)

    with open("/var/lib/insights/host-details.json", mode="w+b") as f:
        f.write(content)
        logger.debug("Wrote \"/var/lib/insights/host-details.json\"")

    host_id = host_details["results"][0]["id"]
    url = self.base_url + "/insights/v1/system/%s/reports/" % host_id
    content = self._get(url)
    if content is None:
        return None

    with open("/var/lib/insights/insights-details.json", mode="w+b") as f:
        f.write(content)
        logger.debug("Wrote \"/var/lib/insights/insights-details.json\"")

    return json.loads(content)



# -LEGACY-
def register(config, pconn):
    """
    Do registration using basic auth
    """
    username = config.username
    password = config.password
    authmethod = config.authmethod
    auto_config = config.auto_config
    if not username and not password and not auto_config and authmethod == 'BASIC':
        logger.debug('Username and password must be defined in configuration file with BASIC authentication method.')
        return False
    return pconn.register()


def handle_registration(config, pconn):
    '''
    Does nothing on the platform. Will be deleted eventually.
    '''
    if config.legacy_upload:
        return _legacy_handle_registration(config, pconn)


def get_registration_status(config, pconn):
    '''
        Handle the registration process
        Returns:
            True - machine is registered
            False - machine is unregistered
            None - could not reach the API
    '''
    return registration_check(pconn)


# -LEGACY-
def _legacy_handle_unregistration(config, pconn):
    """
        returns (bool): True success, False failure
    """
    check = get_registration_status(config, pconn)

    for m in check['messages']:
        logger.debug(m)

    if check['unreachable']:
        # Run connection test and exit
        return None

    if check['status']:
        unreg = pconn.unregister()
    else:
        unreg = True
        logger.info('This system is already unregistered.')
    if unreg:
        # only set if unreg was successful
        write_unregistered_file()
        get_scheduler(config).remove_scheduling()
        delete_cache_files()
    return unreg


def handle_unregistration(config, pconn):
    """
    Returns:
        True - machine was successfully unregistered
        False - machine could not be unregistered
        None - could not reach the API
    """
    if config.legacy_upload:
        return _legacy_handle_unregistration(config, pconn)

    unreg = pconn.unregister()
    if unreg:
        # only set if unreg was successful
        write_unregistered_file()
        delete_cache_files()
    return unreg