# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
'''vFXT Cluster management

Cookbook/examples:

# A cluster is built with a service object (aws or gce)
service = vFXT.aws.Service() | vFXT.gce.Service()

# create a cluster
cluster = Cluster.create(service, ...)

# load from an existing, online cluster (queries xmlrpc)
cluster = Cluster.load(service, mgmt_ip='xxx', admin_password='xxx')

# offline with node instance ids provided
cluster = Cluster(service=service,
            nodes=['node-1', 'node-2', 'node-1'],
            admin_password='password',
            mgmt_ip='10.10.10.10')

serializeme = cluster.export()
cluster = Cluster(service, **serializeme)

cluster.start()
cluster.stop()
cluster.restart()
cluster.destroy()

cluster.shelve()
cluster.unshelve()

cluster.is_on()
cluster.is_off()
cluster.is_shelved()
cluster.status()

cluster.wait_for_healthcheck()
cluster.wait_for_service_checks()
cluster.wait_for_cluster_activity()
cluster.wait_for_nodes_to_join()

cluster_cfg = cluster.cluster_config()
joincfg = cluster.cluster_config(joining=True)

cluster.in_use_addresses()


rpc = cluster.xmlrpc()
cluster.verify_license()
cluster.upgrade('http://path/to/armada.pkg')

# buckets
cluster.make_test_bucket(bucketname='unique_bucket', corefiler='cloudfiler')
# or
service.create_bucket('unique_bucket')
cluster.attach_bucket('cloudfiler', 'mypassword', 'unique_bucket')
cluster.add_vserver('vserver')
cluster.add_vserver_junction('vserver','cloudfiler')

# NFS filer
cluster.attach_corefiler('grapnel', 'grapnel.lab.avere.net')
cluster.add_vserver_junction('vserver', 'grapnel', path='/nfs', export='/vol/woodwardj')

# maint
cluster.enable_ha()
cluster.rebalance_directory_managers()

cluster.refresh()
cluster.reload()


# Full AWS example
cluster = Cluster.create(aws, 'r3.2xlarge', 'mycluster', 'adminpass',
                        subnet='subnet-f99a618e',
                        placement_group='perf1',
                        wait_for_state='yellow')
try:
    cluster.make_test_bucket(bucketname='mycluster-bucket', corefiler='aws')
    cluster.add_vserver('vserver')
    cluster.add_vserver_junction('vserver', 'aws')
except Exception as e:
    cluster.destroy()
    raise


'''

import threading
import Queue
import time
import logging
import uuid
import re
import socket
from xmlrpclib import Fault as xmlrpclib_Fault
import math
import itertools

import vFXT.xmlrpcClt
from vFXT.serviceInstance import ServiceInstance
from vFXT.service import *
from vFXT.cidr import Cidr

log = logging.getLogger(__name__)

class Cluster(object):
    '''Cluster representation

        Cluster composes the backend service object and performs all
        operations through it or the XMLRPC client.

    '''
    CONFIGURATION_EXPIRATION = 1800
    JOIN_CONFIGURATION_EXPIRATION = 7200
    LICENSE_TIMEOUT = 120

    def __init__(self, service, **options):
        '''Constructor

            The only required argument is the service backend.

            To create a cluster, use Cluster.create()

            To load a cluster, use Cluster.load()

            Arguments:
                service: the backend service
                nodes ([], optional): optional list of node IDs
                mgmt_ip (str, optional): management address
                admin_password (str, optional): administration password
                name (str, optional): cluster name
                machine_type (str, optional): machine type of nodes in the cluster
                mgmt_netmask (str, optional): netmask of management network
                proxy_uri (str, optional): URI of proxy resource (e.g. http://user:pass@172.16.16.20:8080)

            If called with mgmt_ip and admin_password, the cluster object will
            query the management address and fill in all of the details required.

            If called with just a list of node IDs, the cluster will lookup the
            service instance backing objects associated with the node IDs.
            This is handy for offline clusters.
        '''
        self.service          = service
        self.nodes            = options.get('nodes',            [])
        self.mgmt_ip          = options.get('mgmt_ip',          None)
        self.admin_password   = options.get('admin_password',   None)
        self.name             = options.get('name',             None)
        self.machine_type     = options.get('machine_type',     None)

        self.mgmt_netmask     = options.get('mgmt_netmask',     None)
        self.cluster_ip_start = options.get('cluster_ip_start', None)
        self.cluster_ip_end   = options.get('cluster_ip_end',   None)
        self.proxy            = options.get('proxy_uri',        None)
        self.join_mgmt        = True
        self.trace_level      = None
        self.node_rename      = True
        self.first_node_error = None
        self.timezone         = None
        self.instance_addresses = []

        if self.proxy:
            self.proxy = validate_proxy(self.proxy) # imported from vFXT.service

        # we may be passed a list of instance IDs for offline clusters that we
        # can't query
        if self.service and self.nodes and all([not isinstance(i, ServiceInstance) for i in self.nodes]):
            instances = []
            for node_id in self.nodes:
                log.debug("Loading node {}".format(node_id))
                instance = service.get_instance(node_id)
                if not instance:
                    raise vFXTConfigurationException("Unable to find instance {}".format(node_id))
                instances.append(ServiceInstance(service=self.service, instance=instance))
            self.nodes = instances

        if self.mgmt_ip and self.admin_password and self.nodes and self.is_on():
            # might as well if we can, otherwise use the load() constructor
            self.load_cluster_information()

    @classmethod
    def create(cls, service, machine_type, name, admin_password, **options):
        '''Create a cluster

            Arguments:
                service: the backend service
                machine_type (str): service specific machine type
                name (str): cluster name (used or all subsequent resource naming)
                admin_password (str): administration password to assign to the cluster
                wait_for_state (str, optional): red, yellow, green cluster state (defaults to yellow)
                wait_for_state_duration (int, optional): number of seconds state must be maintained, defaults to 30
                proxy_uri (str, optional): URI of proxy resource (e.g. http://user:pass@172.16.16.20:8080)
                skip_cleanup (bool, optional): do not clean up on failure
                management_address (str, optional): management address for the cluster
                trace_level (str, optional): trace configuration
                timezone (str, optional): Set cluster timezone
                join_instance_address (bool, optional): Join cluster using instance rather than management address (defaults to True)
                skip_node_renaming (bool optional): Do not automatically configure and enforce node naming convention (defaults to False)
                size (int, optional): size of cluster (node count), defaults to 3
                root_image (str, optional): root disk image name
                address_range_start (str, optional): The first of a custom range of addresses to use for the cluster
                address_range_end (str, optional): The last of a custom range of addresses to use for the cluster
                address_range_netmask (str, optional): cluster address range netmask
                instance_addresses ([str], optional): list of instance IP addresses to assign to the cluster nodes
                **options: passed to Service.create_cluster()
        '''

        c                 = cls(service)
        c.admin_password  = admin_password or '' # could be empty
        c.machine_type    = machine_type
        c.name            = name
        c.proxy           = options.get('proxy_uri', None)
        c.trace_level     = options.get('trace_level', None)
        c.timezone        = options.get('timezone', None)
        c.join_mgmt       = False if options.get('join_instance_address', True) else True

        if c.proxy:
            c.proxy = validate_proxy(c.proxy) # imported from vFXT.service
        if options.get('skip_node_renaming'):
            c.node_rename = False
        if not options.get('size'):
            options['size'] = 3
        cluster_size = int(options['size'])

        if not name:
            raise vFXTConfigurationException("A cluster name is required")
        if not cls.valid_cluster_name(name):
            raise vFXTConfigurationException("{} is not a valid cluster name".format(name))
        if options.get('management_address'):
            c.mgmt_ip = options.get('management_address')
            if service.in_use_addresses('{}/32'.format(c.mgmt_ip)):
                raise vFXTConfigurationException("The requested management address {} is already in use".format(c.mgmt_ip))

        # Need to validate if instance_addresses passed in are already in use before creating the cluster
        if options.get('instance_addresses'):
            try:
                already_in_use = []
                for address in options['instance_addresses']:
                    if service.in_use_addresses('{}/32'.format(address)):
                        already_in_use.append(address)
                if already_in_use:
                    raise vFXTConfigurationException("The requested instance addresses are already in use: {}".format(', '.join(already_in_use)))

                if len(options['instance_addresses']) != cluster_size:
                    raise vFXTConfigurationException("Not enough instance addresses provided, require {}".format(cluster_size))

            except vFXTConfigurationException:
                raise
            except Exception as e:
                log.debug(e)
                raise vFXTConfigurationException("Invalid instance addresses: {}".format(options['instance_addresses']))
            c.instance_addresses = options['instance_addresses']

        # determine how many addresses we need
        instance_count = cluster_size if (service.ALLOCATE_INSTANCE_ADDRESSES and not c.instance_addresses) else 0
        management_count = 0 if options.get('management_address') else 1
        ip_count = cluster_size + instance_count + management_count

        if all([options.get(_) for _ in ['address_range_start', 'address_range_end', 'address_range_netmask']]):
            try:
                already_in_use = []
                cluster_range = Cidr.expand_address_range(options.get('address_range_start'), options.get('address_range_end'))
                for address in cluster_range:
                    if c.service.in_use_addresses('{}/32'.format(address)):
                        already_in_use.append(address)
                if already_in_use:
                    raise vFXTConfigurationException("The requested instance addresses are already in use: {}".format(', '.join(already_in_use)))

                if len(cluster_range) < ip_count:
                    raise vFXTConfigurationException("Not enough addresses provided, require {}".format(ip_count))

                log.debug("Using overrides for cluster management and address range")
                if management_count:
                    c.mgmt_ip = cluster_range[0]
                if instance_count:
                    c.instance_addresses = cluster_range[management_count:instance_count + management_count]
                c.cluster_ip_start = cluster_range[management_count + instance_count]
                c.cluster_ip_end = cluster_range[-1]
                c.mgmt_netmask = options['address_range_netmask']
            except vFXTConfigurationException:
                raise
            except Exception as e:
                log.debug(e)
                raise vFXTConfigurationException("Invalid instance addresses: {}".format(options['instance_addresses']))
        else:
            in_use_addresses = []
            if c.mgmt_ip:
                in_use_addresses.append(c.mgmt_ip)
            if c.instance_addresses:
                in_use_addresses.extend(c.instance_addresses)
            avail, mask = service.get_available_addresses(count=ip_count, contiguous=True, in_use=in_use_addresses)
            if management_count:
                c.mgmt_ip = avail[0]
            if instance_count:
                c.instance_addresses = avail[management_count:instance_count + management_count]
            c.cluster_ip_start = avail[management_count + instance_count]
            c.cluster_ip_end = avail[-1]
            c.mgmt_netmask = mask

        # machine type is validated by service create_cluster

        try:
            service.create_cluster(c, **options)
            if options.get('skip_configuration'):
                return c
        except KeyboardInterrupt:
            if not options.get('skip_cleanup', False):
                c.destroy(quick_destroy=True)
            raise

        try:
            # any service specific instance checks should happen here... the checks
            # might have to restart the nodes
            c.wait_for_service_checks()

            xmlrpc = c.xmlrpc()
            retries = int(options.get('join_wait', 500 + (500 * math.log(len(c.nodes)))))

            # should get all the nodes joined by now
            c.allow_node_join(retries=retries, xmlrpc=xmlrpc)
            c.wait_for_nodes_to_join(retries=retries, xmlrpc=xmlrpc)
            c.allow_node_join(enable=False, retries=retries, xmlrpc=xmlrpc)

            c.set_node_naming_policy(xmlrpc=xmlrpc)
            if len(c.nodes) > 1:
                c.enable_ha(xmlrpc=xmlrpc)
            c.verify_license(xmlrpc=xmlrpc)

            log.info("Waiting for cluster healthcheck")
            c.wait_for_healthcheck(state=options.get('wait_for_state', 'yellow'),
                duration=int(options.get('wait_for_state_duration', 30)), xmlrpc=xmlrpc)
        except (KeyboardInterrupt, Exception) as e:
            log.error("Cluster configuration failed: {}".format(e))
            if not options.get('skip_cleanup', False):
                c.destroy(quick_destroy=True)
            else:
                try:
                    c.telemetry()
                except Exception as te:
                    log.debug(te)
            raise vFXTCreateFailure(e)

        return c

    def wait_for_healthcheck(self, state='green', retries=ServiceBase.WAIT_FOR_HEALTH_CHECKS, duration=1, conn_retries=1, xmlrpc=None):
        '''Poll for cluster maxConditions
            This requires the cluster to be on and be accessible via RPC

            Arguments:
                state (str='green'): red, yellow, green
                retries (int, optional): number of retries
                duration (int, optional): number of consecutive seconds condition was observed
                conn_retries (int, optional): number of connection retries
                xmlrpc (xmlrpcClt, optional): xmlrpc client

            Sleeps Service.POLLTIME between each retry.
        '''
        retries      = int(retries)
        conn_retries = int(conn_retries)
        duration     = int(duration)
        log.info("Waiting for healthcheck")
        xmlrpc = self.xmlrpc(conn_retries) if xmlrpc is None else xmlrpc

        start_time = int(time.time())
        observed = 0 # observed time in the requested state

        # cluster health check
        acceptable_states = [state, 'green']
        if state == 'red':
            acceptable_states.append('yellow')
        while True:
            alertstats = {}
            try:
                alertstats = xmlrpc.cluster.maxActiveAlertSeverity()
            except Exception as e:
                log.debug("Ignoring cluster.maxActiveAlertSeverity() failure: {}".format(e))
                xmlrpc = self.xmlrpc(conn_retries)

            if 'maxCondition' in alertstats and alertstats['maxCondition'] in acceptable_states:
                observed = int(time.time()) - start_time
                if observed >= duration:
                    log.debug("{} for {}s({})... alertStats: {}".format(state, duration, observed, alertstats))
                    break
            else:
                observed = 0
                start_time = int(time.time())

            if retries % 10 == 0:
                self._log_conditions(xmlrpc)
                log.debug("Not {} for {}s({})... alertStats: {}".format(state, duration, observed, alertstats))

            retries -= 1
            if retries == 0:
                alert_codes = []
                try:
                    conditions  = xmlrpc.alert.conditions()
                    alert_codes = [c['name'] for c in conditions if c['severity'] != state]
                except Exception as e:
                    log.debug("Failed to get alert conditions: {}".format(e))
                    xmlrpc = self.xmlrpc(conn_retries)
                if alert_codes:
                    raise vFXTStatusFailure("Healthcheck for state {} failed: {}".format(state, alert_codes))
                else:
                    raise vFXTStatusFailure("Healthcheck for state {} failed".format(state))
            self._sleep()

    @classmethod
    def load(cls, service, mgmt_ip, admin_password):
        '''Load an existing cluster over RPC

            Arguments:
                mgmt_ip (str): management address
                admin_password (str): administration password
        '''
        cluster                 = cls(service)
        cluster.mgmt_ip         = mgmt_ip
        cluster.admin_password  = admin_password

        cluster.load_cluster_information()
        return cluster

    def load_cluster_information(self):
        '''Load cluster information through XMLRPC and the service backend

            Raises: vFXTConfigurationException
        '''
        log.debug("Connecting to {} to load cluster data".format(self.mgmt_ip))
        xmlrpc          = self.xmlrpc()
        cluster_data    = self._xmlrpc_do(xmlrpc.cluster.get)
        self.name       = cluster_data['name']
        self.mgmt_netmask = cluster_data['mgmtIP']['netmask']
        expected_count  = len(self._xmlrpc_do(xmlrpc.node.list))

        log.debug("Loading {} nodes".format(self.name))
        self.service.load_cluster_information(self)
        if not self.nodes:
            raise vFXTConfigurationException("No nodes found for cluster")

        found_count = len(self.nodes)
        if expected_count != found_count:
            raise vFXTStatusFailure("Failed to load all {} nodes (found {})".format(expected_count, found_count))

    def cluster_config(self, joining=False, expiration=CONFIGURATION_EXPIRATION, joining_expiration=JOIN_CONFIGURATION_EXPIRATION):
        '''Return cluster configuration for master and slave nodes

            Arguments:
                joining (bool, optional): configuration for a joining node
                expiration (int, optional): configuration expiration for a joining node

            Raises: vFXTConfigurationException
        '''

        if joining:
            expiry = str(int(time.time()) + (joining_expiration or self.JOIN_CONFIGURATION_EXPIRATION))
            mgmt_ip = (self.nodes[0].ip() if self.nodes and not self.join_mgmt else self.mgmt_ip)
            return '# cluster.cfg\n[basic]\njoin cluster={}\nexpiration={}\n'.format(mgmt_ip, expiry)

        expiry      = str(int(time.time()) + (expiration or self.CONFIGURATION_EXPIRATION))
        dns_servs   = self.service.get_dns_servers()
        ntp_servs   = self.service.get_ntp_servers()
        router      = self.service.get_default_router()

        if not all([self.mgmt_ip, self.mgmt_netmask, self.cluster_ip_start, self.cluster_ip_end]):
            raise vFXTConfigurationException("Management IP/Mask and the cluster IP range is required")

        # generate config
        config = '''# cluster.cfg''' \
                 '''\n[basic]''' \
                 '''\ncluster name={}''' \
                 '''\npassword={}''' \
                 '''\nexpiration={}''' \
                 '''\n[management network]''' \
                 '''\naddress={}''' \
                 '''\nnetmask={}''' \
                 '''\ndefault router={}''' \
                 '''\n[cluster network]''' \
                 '''\nfirst address={}''' \
                 '''\nlast address={}'''  \
                .format(self.name,
                        self.admin_password,
                        expiry,
                        self.mgmt_ip,
                        self.mgmt_netmask,
                        router,
                        self.cluster_ip_start,
                        self.cluster_ip_end)

        config += '\n[dns]\n'
        dns_count = len(dns_servs)
        for idx in range(3):
            v = dns_servs[idx] if idx < dns_count else ''
            config += 'server{}={}\n'.format(idx + 1, v)
        config += 'domain=\n'

        config += '\n[ntp]\n'
        ntp_count = len(ntp_servs)
        for idx in range(3):
            v = ntp_servs[idx] if idx < ntp_count else ''
            config += 'server{}={}\n'.format(idx + 1, v)

        return config

    def verify_license(self, wait=LICENSE_TIMEOUT, xmlrpc=None):
        '''Verify a license has been provisioned for the cluster

            Arguments:
                wait (int): time to wait in seconds for the license provisioning (default 60)
                xmlrpc (xmlrpcClt, optional): xmlrpc client

            Raises: vFXTConfigurationException
        '''
        if self.service.AUTO_LICENSE:
            return

        log.info('Waiting for FlashCloud licensing feature')
        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc
        while wait > 0:
            try:
                licenses = xmlrpc.cluster.listLicenses()
                if 'FlashCloud' in licenses['features']:
                    log.info('Feature FlashCloud enabled.')
                    return
            except Exception as e:
                log.debug(e)
            if wait % 10 == 0:
                log.debug('Waiting for the FlashCloud license feature to become enabled')
            wait -= 1
            self._sleep()

        raise vFXTConfigurationException("Unable to verify cluster licensing")

    def xmlrpc(self, retries=1, password=None):
        '''Connect and return a new RPC connection object

            Arguments:
                retries (int, optional): number of retries
                password (str, optional): defaults to the cluster admin_password

            Raises: vFXTConnectionFailure
        '''
        addrs = []
        if self.join_mgmt:
            addrs.append(self.mgmt_ip)
        if self.nodes:
            addrs.append(self.nodes[0].ip())
        if not addrs:
            raise vFXTConfigurationException("No usable connection address for xmlrpc calls")

        password = password or self.admin_password
        if not password:
            raise vFXTConnectionFailure("Unable to make remote API connection without a password")

        while True:
            # try our mgmt address or the first nodes instance address
            for addr in addrs:
                try:
                    xmlrpc = vFXT.xmlrpcClt.getXmlrpcClient("https://{}/cgi-bin/rpc2.py".format(addr), do_cert_checks=False)
                    xmlrpc('transport').user_agent = 'vFXT/{}'.format(vFXT.__version__)
                    xmlrpc.system.login( "admin".encode('base64'), password.encode('base64') )
                    if addr != self.mgmt_ip and self.join_mgmt:
                        log.warn("Connected via instance address {} instead of management address {}".format(addr, self.mgmt_ip))
                        self._log_conditions(xmlrpc)
                    return xmlrpc
                except Exception as e:
                    log.debug("Retrying failed XMLRPC connection to {}: {}".format(addr, e))
                    if retries == 0:
                        raise vFXTConnectionFailure("Failed to make remote API connection: {}".format(e))
            retries -= 1
            self._sleep()

    def _xmlrpc_do(self, f, *args, **kwargs):
        '''Run an xmlrpc function, retrying depending on the xmlrpc Fault

            Arguments:
                f (callable): rpc proxy function to call
                *args: rpc arg list
                **kwargs: rpc arg keywords

            _xmlrpc_do_retries kwarg is special, defaults to XMLRPC_RETRIES

            Retry errors include
                100 AVERE_ERROR
                102 AVERE_ENOENT
                109 AVERE_EBUSY
        '''
        retry_errors = [100, 102, 109]
        retries = kwargs.pop('_xmlrpc_do_retries', self.service.XMLRPC_RETRIES)
        while True:
            try:
                return f(*args, **kwargs)
            except xmlrpclib_Fault as e:
                log.debug("avere xmlrpc failure: {}".format(e))
                if retries == 0 or int(e.faultCode) not in retry_errors:
                    raise
            except Exception as e:
                log.debug("avere xmlrpc failure: {}".format(e))
                if retries == 0:
                    raise
            retries -= 1
            self._sleep()

    def _xmlrpc_wait_for_activity(self, activity, error_msg, retries=None):
        '''Wait for a xmlrpc activity to complete

            Arguments:
            activity (str): cluster activity UUID
            error_msg (str): Exception text on error
            retries (int, optional): max retries, otherwise loops indefinitely
        '''
        if activity == 'success':
            return

        xmlrpc = self.xmlrpc()
        tries = 0
        while True:
            response = {}
            try:
                if xmlrpc is None:
                    xmlrpc = self.xmlrpc()
                response = xmlrpc.cluster.getActivity(activity)
                log.debug(response)
            except Exception as e:
                log.exception("Failed to get activity {}: {}".format(activity, e))
                xmlrpc = None

            if 'state' in response:
                if response['state'] == 'success':
                    break
                if response['state'] == 'failure':
                    err = '{}: {}'.format(error_msg, response.get('status', 'Unknown'))
                    raise vFXTConfigurationException(err)
            if retries is not None:
                if retries == 0:
                    err = '{}: Timed out while {}'.format(error_msg, response['status'])
                    raise vFXTConfigurationException(err)
                retries -= 1
            if tries % 10 == 0 and 'status' in response:
                log.info(response['status'])
                self._log_conditions(xmlrpc)
            self._sleep()
            tries += 1

    def _enable_maintenance_api(self, xmlrpc):
        response = self._xmlrpc_do(xmlrpc.system.enableAPI, 'maintenance')
        if response != 'success':
            raise vFXTConfigurationException('Failed to enable maintenance API')

    @classmethod
    def _log_conditions(cls, xmlrpc):
        '''Debug log the conditions

            This is useful when we are polling and want to show what is going
            on with the cluster while we wait.

            Arguments:
                xmlrpc (xmlrpcClt): xmlrpc client
        '''
        if not log.isEnabledFor(logging.DEBUG):
            return
        try:
            conditions = xmlrpc.alert.conditions()
            log.debug("Current conditions: {}".format(conditions))
        except Exception as e:
            log.debug("Failed to get condition list: {}".format(e))

    def telemetry(self, wait=True, retries=ServiceBase.WAIT_FOR_TELEMETRY, mode='gsimin'):
        '''Kick off a minimal telemetry reporting

            Arguments:
                wait (bool, optional): wait until complete
                retries (int, optional): number of retries to wait (if wait is disabled)
                mode (str, optional): telemetry mode (valid from support.listNormalModes)

            Raises vFXTStatusFailure on failure while waiting.
        '''
        if mode not in self.xmlrpc().support.listNormalModes()[0]:
            raise vFXTConfigurationException("Invalid support mode {}".format(mode))

        try:
            log.info("Kicking off {} telemetry reporting.".format(mode))
            response = self.xmlrpc().support.executeNormalMode('cluster', mode)
            log.debug('{} response {}'.format(mode, response))
            if not wait:
                return
            if response != 'success':
                while True:
                    try:
                        is_done = self.xmlrpc().support.taskIsDone(response) # returns bool
                        if is_done:
                            break
                    except Exception as e:
                        log.debug("Error while checking for telemetry status: {}".format(e))
                    if retries % 10 == 0:
                        log.debug('Waiting for {} to complete'.format(response))
                    retries -= 1
                    if retries == 0:
                        raise vFXTConfigurationException("Time out waiting for telemetry upload to finish")
                    self._sleep()
        except Exception as e:
            log.debug("Telemetry failed: {}".format(e))
            raise vFXTStatusFailure('Telemetry failed: {}'.format(e))

    def upgrade_alternate_image(self, upgrade_url, retries=None):
        '''Upgrade the cluster alternate image

            Arguments:
                upgrade_url (str): URL for armada package
                retries (int, optional): retry count for switching active images
        '''
        retries     = retries or int(500 + (500 * math.log(len(self.nodes))))
        xmlrpc      = self.xmlrpc()
        cluster     = self._xmlrpc_do(xmlrpc.cluster.get)
        alt_image   = cluster['alternateImage']

        upgrade_status = self._xmlrpc_do(xmlrpc.cluster.upgradeStatus)
        if not upgrade_status.get('allowDownload', False):
            raise vFXTConfigurationException("Upgrade downloads are not allowed at this time")

        # note any existing activities to skip
        existing_activities = [a['id'] for a in self._xmlrpc_do(xmlrpc.cluster.listActivities)]

        log.info("Fetching alternate image from {}".format(upgrade_url))
        response = self._xmlrpc_do(xmlrpc.cluster.upgrade, upgrade_url)
        if response != 'success':
            raise vFXTConfigurationException("Failed to start upgrade download: {}".format(response))

        op_retries = retries
        while cluster['alternateImage'] == alt_image:
            self._sleep()
            try:
                cluster    = self._xmlrpc_do(xmlrpc.cluster.get)
                activities = [act for act in self._xmlrpc_do(xmlrpc.cluster.listActivities)
                                if act['id'] not in existing_activities # skip existing
                                if act['process'] == 'Cluster upgrade' # look for cluster upgrade or download
                                or 'software download' in act['process']]
                failures = [_ for _ in activities if 'failure' in _['state']]
                if failures:
                    errmsg = ', '.join([': '.join([_['process'], _['status']]) for _ in failures])
                    raise vFXTConfigurationException("Failed to download upgrade image: {}".format(errmsg))
                if op_retries % 10 == 0:
                    log.debug('Current activities: {}'.format(', '.join([act['status'] for act in activities])))

                # check for double+ upgrade to same version
                existing_ver_msg = 'Download {} complete'.format(alt_image)
                if existing_ver_msg in [act['status'] for act in activities]:
                    log.debug("Redownloaded existing version")
                    break

            except vFXTConfigurationException as e:
                log.debug(e)
                raise
            except Exception as e:
                if op_retries % 10 == 0:
                    log.debug("Retrying install check: {}".format(e))
            op_retries -= 1
            if op_retries == 0:
                raise vFXTConnectionFailure("Timeout waiting for alternate image")

        log.info("Updated alternate image to {}".format(cluster['alternateImage']))

    def activate_alternate_image(self, retries=None, ha=True):
        '''Activate the alternate image

            Arguments:
                retries (int, optional): retry count for switching active images, default is no retries
                ha (bool, optional): do an HA upgrade, True
        '''
        cluster = self._xmlrpc_do(self.xmlrpc().cluster.get)
        if cluster['alternateImage'] == cluster['activeImage']:
            log.info("Skipping upgrade since this version is active")
            return
        alt_image = cluster['alternateImage']

        if not ha: # if not HA, at least suspend the vservers
            vservers = self._xmlrpc_do(self.xmlrpc().vserver.list)
            for vserver in vservers:
                log.info("Suspending vserver {} on cluster {}".format(vserver, cluster['name']))
                activity = self._xmlrpc_do(self.xmlrpc().vserver.suspend, vserver)
                self._xmlrpc_wait_for_activity(activity, "Failed to suspend vserver {}".format(vserver))

        log.debug("Waiting for alternateImage to settle (FIXME)...")
        self._sleep(15) # time to settle?
        upgrade_status = self._xmlrpc_do(self.xmlrpc().cluster.upgradeStatus)
        if not upgrade_status.get('allowActivate', False):
            raise vFXTConfigurationException("Alternate image activation is not allowed at this time")

        log.info("Activating alternate image")
        response = self._xmlrpc_do(self.xmlrpc().cluster.activateAltImage, ha)
        log.debug("activateAltImage response: {}".format(response))

        existing_activities = [a['id'] for a in self._xmlrpc_do(self.xmlrpc().cluster.listActivities)]
        log.debug("existing activities prior to upgrade: {}".format(existing_activities))

        tries = 0
        while cluster['activeImage'] != alt_image:
            self._sleep()
            try:
                # we may end up with hung connections as our VIFs move...
                def signal_handler(signum, stack):
                    log.debug("Signal handler for sig {}: {}".format(signum, stack))
                    raise vFXTConnectionFailure("Connection alarm raised")
                import signal
                if hasattr(signal, 'alarm') and hasattr(signal, 'SIGALRM'):
                    signal.signal(signal.SIGALRM, signal_handler)
                    signal.alarm(60)

                cluster    = self._xmlrpc_do(self.xmlrpc().cluster.get)
                activities = [act for act in self._xmlrpc_do(self.xmlrpc().cluster.listActivities)
                                if act['id'] not in existing_activities # skip existing
                                if act['process'] == 'Cluster upgrade' # look for cluster upgrade or activate
                                or 'software activate' in act['process']]
                if 'failed' in [a['state'] for a in activities]:
                    raise vFXTConfigurationException("Failed to activate alternate image")
                if tries % 10 == 0:
                    log.info('Waiting for active image to switch to {}'.format(alt_image))
                    activity_status = ', '.join([act['status'] for act in activities])
                    if activity_status:
                        log.debug('Current activities: {}'.format(activity_status))
                tries += 1
            except vFXTConfigurationException as e:
                log.debug(e)
                raise
            except Exception as e:
                log.debug("Retrying upgrade check: {}".format(e))
            finally:
                # reset SIGALRM handler
                if hasattr(signal, 'alarm') and hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, signal.SIG_DFL)

            if retries is not None:
                retries -= 1
                if retries == 0:
                    raise vFXTConnectionFailure("Timeout waiting for active image")

        if not ha: # if not HA, we suspended the vservers.... undo here
            vservers = self._xmlrpc_do(self.xmlrpc().vserver.list)
            for vserver in vservers:
                log.info("Unsuspending vserver {} on cluster {}".format(vserver, cluster['name']))
                activity = self._xmlrpc_do(self.xmlrpc().vserver.unsuspend, vserver)
                self._xmlrpc_wait_for_activity(activity, "Failed to unsuspend vserver {}".format(vserver))

        log.info("Upgrade to {} complete".format(alt_image))


    def upgrade(self, upgrade_url, retries=None, ha=True):
        '''Upgrade a cluster from the provided URL

            Arguments:
                upgrade_url (str): URL for armada package
                retries (int, optional): retry count for switching active images
                ha (bool, optional): do an HA upgrade, True

            Raises: vFXTConnectionFailure
        '''
        self.upgrade_alternate_image(upgrade_url, retries=retries)
        self.activate_alternate_image(ha=ha, retries=retries)

    def add_nodes(self, count=1, **options):
        '''Add nodes to the cluster

            This extends the address ranges of the cluster and all configured
            vservers (if required) to accommodate the new nodes.

            Arguments:
                count (int, optional): number of nodes to add
                skip_cleanup (bool, optional): do not clean up on failure
                join_wait (int, optional): join wait time (defaults to wait_for_nodes_to_join default)
                skip_node_renaming (bool optional): Do not automatically configure and enforce node naming convention (defaults to False)
                address_range_start (str, optional): Specify the first of a custom range of addresses to use
                address_range_end (str, optional): Specify the last of a custom range of addresses to use
                address_range_netmask (str, optional): Specify the netmask of the custom address range to use
                vserver_home_addresses (bool, optional): Update address home configuration for all vservers
                **options: options to pass to the service backend

            Raises: vFXTCreateFailure


            On failure, undoes cluster and vserver configuration changes.
        '''
        self.reload()
        log.info("Extending cluster {} by {}".format(self.name, count))

        node_count = len(self.nodes)
        if not node_count:
            raise vFXTConfigurationException("Cannot add a node to an empty cluster")

        self.service._add_cluster_nodes_setup(self, count, **options)

        # check to see if we can add nodes with the current licensing information
        xmlrpc           = self.xmlrpc()
        license_data     = self._xmlrpc_do(xmlrpc.cluster.listLicenses)
        licensed_count   = int(license_data['maxNodes'])
        if (node_count + count) > licensed_count:
            msg = "Cannot expand cluster to {} nodes as the current licensed maximum is {}"
            raise vFXTConfigurationException(msg.format(node_count + count, licensed_count))

        cluster_data     = self._xmlrpc_do(xmlrpc.cluster.get)
        cluster_ips_per_node = int(cluster_data['clusterIPNumPerNode'])
        vserver_count    = len(self._xmlrpc_do(xmlrpc.vserver.list))
        existing_vserver = self.in_use_addresses('vserver', xmlrpc=xmlrpc)
        existing_cluster = self.in_use_addresses('cluster', xmlrpc=xmlrpc)
        need_vserver     = ((node_count + count) * vserver_count) - len(existing_vserver)
        need_cluster     = ((node_count + count) * cluster_ips_per_node) - len(existing_cluster)
        need_cluster     = need_cluster if need_cluster > 0 else 0
        need_vserver     = need_vserver if need_vserver > 0 else 0
        need_instance    = count if self.service.ALLOCATE_INSTANCE_ADDRESSES else 0
        in_use_addrs     = self.in_use_addresses(xmlrpc=xmlrpc)

        if options.get('instance_addresses'):
            # check that the instance addresses are not already used by the cluster
            try:
                existing = []
                for address in options['instance_addresses']:
                    if address in in_use_addrs:
                        existing.append(address)
                    else:
                        # otherwise we should note our intent to use it
                        in_use_addrs.append(address)
                        # also check if another instance is using the address
                        if self.service.in_use_addresses('{}/32'.format(address)):
                            existing.append(address)
                if existing:
                    raise vFXTConfigurationException("Instance addresses are already in use: {}".format(existing))

                if len(options['instance_addresses']) < count:
                    raise vFXTConfigurationException("Not enough instance addresses provided, require {}".format(count))
            except vFXTConfigurationException:
                raise
            except Exception as e:
                log.debug(e)
                raise vFXTConfigurationException("Invalid instance addresses: {}".format(options['instance_addresses']))
            need_instance = 0

        added = [] # cluster and vserver extensions (for undo)

        ip_count = need_vserver + need_cluster + need_instance
        if ip_count > 0: # if we need more, extend ourselves

            custom_ip_config_reqs = ['address_range_start', 'address_range_end', 'address_range_netmask']
            if all([options.get(_) for _ in custom_ip_config_reqs]):
                avail_ips = Cidr.expand_address_range(options.get('address_range_start'), options.get('address_range_end'))
                mask = options.get('address_range_netmask')
                if len(avail_ips) < ip_count:
                    raise vFXTConfigurationException("Not enough addresses provided, require {}".format(ip_count))

                if any([_ in in_use_addrs for _ in avail_ips]):
                    raise vFXTConfigurationException("Specified address range conflicts with existing cluster addresses")
                existing = []
                for address in avail_ips:
                    if self.service.in_use_addresses('{}/32'.format(address)):
                        existing.append(address)
                if existing:
                    raise vFXTConfigurationException("Cluster addresses are already in use: {}".format(existing))
            else:
                avail_ips, mask = self.service.get_available_addresses(count=ip_count, contiguous=True, in_use=in_use_addrs)

            if need_instance:
                options['instance_addresses'] = avail_ips[0:need_instance]
                del avail_ips[0:need_instance]

            if need_cluster > 0:
                addresses = avail_ips[0:need_cluster]
                del avail_ips[0:need_cluster]
                body      = {'firstIP': addresses[0], 'netmask': mask, 'lastIP': addresses[-1]}
                log.info("Extending cluster address range by {}".format(need_cluster))
                log.debug("{}".format(body))
                activity = self._xmlrpc_do(xmlrpc.cluster.addClusterIPs, body)
                self._xmlrpc_wait_for_activity(activity, "Failed to extend cluster addresses")
                added.append({'cluster': body})

            if need_vserver > 0:
                for vserver in self._xmlrpc_do(xmlrpc.vserver.list):
                    v_len     = len([a for r in self._xmlrpc_do(xmlrpc.vserver.get, vserver)[vserver]['clientFacingIPs']
                                for a in xrange(Cidr.from_address(r['firstIP']), Cidr.from_address(r['lastIP']) + 1)])
                    to_add    = (node_count + count) - v_len
                    if to_add < 1:
                        continue

                    addresses = avail_ips[0:to_add]
                    del avail_ips[0:to_add]
                    body      = {'firstIP': addresses[0], 'netmask': mask, 'lastIP': addresses[-1]}
                    log.info("Extending vserver {} address range by {}".format(vserver, need_vserver))
                    log.debug("{}".format(body))
                    activity = self._xmlrpc_do(xmlrpc.vserver.addClientIPs, vserver, body)
                    self._xmlrpc_wait_for_activity(activity, "Failed to extend vserver {} addresses".format(vserver))
                    added.append({'vserver': body})

        # now add the node(s)
        try:
            self.service.add_cluster_nodes(self, count, **options)
            self.wait_for_service_checks()

            # book keeping... may have to wait for a node to update image
            wait = int(options.get('join_wait', 500 + (500 * math.log(count))))
            self.allow_node_join(retries=wait)
            self.wait_for_nodes_to_join(retries=wait)
            self.allow_node_join(enable=False, retries=wait)
            self.refresh()
            self.enable_ha()
            if not options.get('skip_node_renaming'):
                self.set_node_naming_policy()
            if options.get('vserver_home_addresses'):
                self.vserver_home_addresses()
        except (KeyboardInterrupt, Exception) as e:
            log.error(e)
            if options.get('skip_cleanup', False):
                try:
                    self.telemetry()
                except Exception as te:
                    log.debug(te)
                raise vFXTCreateFailure(e)

            log.info("Undoing configuration changes for node addition")

            # our current list
            expected_nodes = [n.id() for n in self.nodes]
            # refresh and get what the cluster sees
            self.service.load_cluster_information(self)
            joined_nodes = [n.id() for n in self.nodes]
            # find the difference
            unjoined = list(set(expected_nodes) ^ set(joined_nodes))
            unjoined_nodes = [ServiceInstance(self.service, i) for i in unjoined]
            # exclude those in the middle of joining
            joining_node_addresses = [_['address'] for _ in self._xmlrpc_do(self.xmlrpc().node.listUnconfiguredNodes) if 'joining' in _['status']]
            unjoined_nodes = [_ for _ in unjoined_nodes if _.ip() not in joining_node_addresses]
            # destroy the difference
            if unjoined_nodes:
                try:
                    self.parallel_call(unjoined_nodes, 'destroy')
                except Exception as destroy_e:
                    log.error('Failed to undo configuration: {}'.format(destroy_e))

            # if we added no nodes successfully, clean up addresses added
            none_joined = len(unjoined) == count
            nothing_created = node_count == len(joined_nodes)
            if none_joined or nothing_created:
                for a in added:
                    if 'vserver' in a:
                        a = a['vserver']
                        for vserver in self._xmlrpc_do(self.xmlrpc().vserver.list):
                            for r in self._xmlrpc_do(self.xmlrpc().vserver.get, vserver)[vserver]['clientFacingIPs']:
                                if r['firstIP'] == a['firstIP'] and r['lastIP'] == a['lastIP']:
                                    log.debug("Removing vserver range {}".format(r))
                                    activity = self._xmlrpc_do(self.xmlrpc().vserver.removeClientIPs, vserver, r['name'])
                                    try:
                                        self._xmlrpc_wait_for_activity(activity, "Failed to undo vserver extension")
                                    except Exception as e:
                                        log.error(e)

                    if 'cluster' in a:
                        a = a['cluster']
                        for r in self._xmlrpc_do(self.xmlrpc().cluster.get)['clusterIPs']:
                            if r['firstIP'] == a['firstIP'] and r['lastIP'] == a['lastIP']:
                                log.debug("Removing cluster range {}".format(r))
                                try:
                                    activity = self._xmlrpc_do(self.xmlrpc().cluster.removeClusterIPs, r['name'])
                                    self._xmlrpc_wait_for_activity(activity, "Failed to undo cluster extension")
                                except Exception as e:
                                    log.error(e)

            raise vFXTCreateFailure(e)

    def parallel_call(self, serviceinstances, method, **options):
        '''Run the named method across all nodes

            A thread is spawned to run the method for each instance.

            Arguments:
                serviceinstances [ServiceInstance]: list of ServiceInstance objects
                method (str): method to call on each ServiceInstance

            Raises: vFXTServiceFailure
        '''
        threads = []
        failq   = Queue.Queue()

        def thread_cb(service, instance_id, q):
            '''thread callback'''
            try:
                # create the instance within the thread, retry initial load prior to calling the method
                retries = service.CLOUD_API_RETRIES
                while True:
                    try:
                        instance = ServiceInstance(service=service, instance_id=instance_id)
                        break
                    except Exception:
                        if retries == 0:
                            raise
                        retries -= 1
                instance.__getattribute__(method)(**options)
            except Exception as e:
                log.error("Failed to {} {}: {}".format(method, instance_id, e))
                if log.isEnabledFor(logging.DEBUG):
                    log.exception(e)
                q.put(("Failed to {} instance {}".format(method, instance_id), e))

        for si in serviceinstances:
            t = threading.Thread(target=thread_cb, args=(si.service, si.instance_id, failq,))
            t.setDaemon(True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        failed = []
        while True:
            try:
                failed.append(failq.get_nowait())
            except Queue.Empty:
                break

        if failed:
            raise vFXTServiceFailure(failed)

    def start(self):
        '''Start all nodes in the cluster'''
        self.parallel_call(self.nodes, 'start')
        self.refresh()

    def can_stop(self):
        '''Some configurations cannot be stopped. Check if this is one.
        '''
        return all([_.can_stop() for _ in self.nodes])

    def stop(self, clean_stop=True, retries=ServiceBase.WAIT_FOR_STOP):
        '''Stop all nodes in the cluster

            Arguments:
                clean_stop (bool, optional): Issues cluster powerdown first (defaults to True)
                retries (int, optional): number of retries (default 600)
        '''

        # we might be only a collection of nodes... make sure we have mgmt ip,
        # password, etc... if so we power down the cluster before calling the
        # service backend stop.
        if clean_stop and (self.admin_password and self.nodes and self.is_on()):

            # if we don't have the mgmt ip, use node1
            if not self.mgmt_ip:
                self.mgmt_ip = self.nodes[0].ip()

            if not all([_.can_stop() for _ in self.nodes]):
                raise vFXTConfigurationException("Node configuration prevents them from being stopped")

            log.info("Powering down the cluster")
            response = self._xmlrpc_do(self.xmlrpc().cluster.powerdown)
            if response != 'success':
                raise vFXTStatusFailure("Failed to power down the cluster: {}".format(response))

            log.info("Waiting for cluster to go offline")
            while self.is_on():
                self._sleep()
                self.refresh()
                retries -= 1
                if retries == 0:
                    raise vFXTStatusFailure("Timed out waiting for the cluster to go offline")


        self.parallel_call(self.nodes, 'stop')
        self.refresh()

    def restart(self):
        '''Calls stop and then start'''
        self.stop()
        self.start()

    def destroy(self, **options):
        '''Destroy the cluster

            Arguments:
                quick_destroy (bool, optional) skip cleanup steps that prevent data loss (defaults to False)
                **options: passed to ServiceInstance.destroy()
        '''
        if not options.pop('quick_destroy', False) and self.is_on() and self.admin_password:
            xmlrpc = self.xmlrpc()
            cluster_name = self.name or 'unknown'

            corefilers = {k: v for _ in self._xmlrpc_do(xmlrpc.corefiler.list) for k, v in self._xmlrpc_do(xmlrpc.corefiler.get, _).items()}
            if corefilers:
                # remove all junctions
                for vserver in self._xmlrpc_do(xmlrpc.vserver.list):
                    log.info("Suspending vserver {} on cluster {}".format(vserver, cluster_name))
                    activity = self._xmlrpc_do(xmlrpc.vserver.suspend, vserver)
                    self._xmlrpc_wait_for_activity(activity, "Failed to suspend vserver {}".format(vserver))
                    for junction in self._xmlrpc_do(xmlrpc.vserver.listJunctions, vserver):
                        log.info("Removing junction {} from vserver {} on cluster {}".format(junction['path'], vserver, cluster_name))
                        activity = self._xmlrpc_do(xmlrpc.vserver.removeJunction, vserver, junction['path'])
                        self._xmlrpc_wait_for_activity(activity, "Failed to remove junction {} from vserver {}".format(junction['path'], vserver))

                for corefiler, data in corefilers.items():
                    # try and call corefiler.flush, note this will raise vFXTConfigurationException
                    # on error... That will bubble up and prevent the rest of the destroy from
                    # completing
                    if data['type'] == 'cloud':
                        self.flush_corefiler(corefiler)
                    # otherwise remove corefilers to force a flush
                    log.info("Removing corefiler {} on cluster {}".format(corefiler, cluster_name))
                    self.remove_corefiler(corefiler)

        self.parallel_call(self.nodes, 'destroy', **options)
        # any post destroy cleanup activities that may be remaining
        self.service.post_destroy_cluster(self)

    def shelve(self, **options):
        '''Shelve all nodes in the cluster'''

        # if we can make rpc calls, try to use maint.setShelve()
        if not self.admin_password or not (self.nodes and self.is_on()):
            raise vFXTConfigurationException('Unable to shelve cluster without xmlrpc connectivity')

        # if we don't have the mgmt ip, use node1
        if not self.mgmt_ip:
            self.mgmt_ip = self.nodes[0].ip()

        if not all([_.can_shelve() for _ in self.nodes]):
            raise vFXTConfigurationException("Node configuration prevents them from being shelved")

        try:
            xmlrpc = self.xmlrpc()
            corefilers = xmlrpc.corefiler.list()

            if corefilers:
                self._enable_maintenance_api(xmlrpc)
                activity = self._xmlrpc_do(xmlrpc.maint.suspendAccess)
                self._xmlrpc_wait_for_activity(activity, "Failed to suspend access", retries=self.service.WAIT_FOR_SUCCESS)

                for corefiler in corefilers:
                    log.debug("Flushing corefiler {}".format(corefiler))
                    self.flush_corefiler(corefiler)
        except xmlrpclib_Fault as e:
            if int(e.faultCode) != 108: # Method not supported
                log.debug("Failed to flush corefilers: {}".format(e))
                raise vFXTConfigurationException(e)
        except Exception as e:
            log.debug("Failed to flush corefilers: {}".format(e))
            raise

        try:
            xmlrpc = self.xmlrpc()
            self._enable_maintenance_api(xmlrpc)
            response = self._xmlrpc_do(xmlrpc.maint.setShelve)
            if response != 'success':
                raise vFXTConfigurationException('Failed to notify cluster of intent to shelve')
            log.debug('Called maint.setShelve()')
        except xmlrpclib_Fault as e:
            if int(e.faultCode) != 108: # Method maint.setShelve not supported
                raise
            log.debug('maint.setShelve not supported in this release')

        self.stop(clean_stop=options.get('clean_stop', True))
        self.parallel_call(self.nodes, 'shelve', **options)
        self.refresh()

    def unshelve(self, **options):
        '''Unshelve all nodes in the cluster'''
        self.parallel_call(self.nodes, 'unshelve', **options)
        self.refresh()
        # we might be only a collection of nodes... make sure we have mgmt ip,
        # password, etc... if so we wait at least until we have api connectivity
        if self.mgmt_ip and self.admin_password and self.nodes and self.is_on():
            self.wait_for_healthcheck(state='red', duration=1, conn_retries=ServiceBase.WAIT_FOR_SUCCESS)

            xmlrpc = self.xmlrpc()
            self._enable_maintenance_api(xmlrpc)
            activity = self._xmlrpc_do(xmlrpc.maint.unsuspendAccess)
            self._xmlrpc_wait_for_activity(activity, "Failed to unsuspend access", retries=self.service.WAIT_FOR_SUCCESS)

    def is_on(self):
        '''Returns true if all nodes are on'''
        if self.nodes:
            return all(i.is_on() for i in self.nodes)
        return False

    def is_off(self):
        '''Returns true if all nodes are off'''
        if self.nodes:
            return all(i.is_off() for i in self.nodes)
        return False

    def is_shelved(self):
        '''Returns true if all nodes are shelved'''
        if self.is_off():
            return all([n.is_shelved() for n in self.nodes])
        else:
            return False

    def status(self):
        '''Returns a list of node id:status'''
        return [{n.id(): n.status() } for n in self.nodes]

    def wait_for_service_checks(self):
        '''Wait for Service checks to complete for all nodes

            This may not be available for all backends and thus may be a noop.
        '''
        self.parallel_call(self.nodes, 'wait_for_service_checks')

    def make_test_bucket(self, bucketname=None, corefiler=None, proxy=None, remove_on_fail=False, **options):
        '''Create a test bucket for the cluster

            Convenience wrapper function for testing.  Calls create_bucket()
            and then attach_bucket().

            Arguments:
                bucketname (str, optional): name of bucket or one is generated
                corefiler (str, optional): name of corefiler or bucketname
                proxy (str, optional): proxy configuration to use
                remove_on_fail (bool, optional): remove the corefiler if the configuration does not finish
                tags (dict, optional): tags with key/value labels to apply to the bucket (if supported)

                **options: passed through to service.create_bucket and cluster.attach_bucket

            Returns:
                key (dict): encryption key for the bucket as returned from attach_bucket
        '''
        bucketname      = bucketname or "{}-{}".format(self.name, str(uuid.uuid4()).lower().replace('-', ''))[0:63]
        corefiler       = corefiler or bucketname
        self.service.create_bucket(bucketname, **options)
        log.info("Created cloud storage {} ".format(bucketname))
        return self.attach_bucket(corefiler, bucketname, proxy=proxy, remove_on_fail=remove_on_fail, **options)

    def attach_bucket(self, corefiler, bucketname, master_password=None, credential=None, proxy=None, **options):
        '''Attach a named bucket as core filer

            Arguments:
                corefiler (str): name of the corefiler to create
                bucketname (str): name of existing bucket to attach
                master_password (str, optional): otherwise cluster admin password is used
                credential (str, optional): cloud credential or one is created or reused by the backing service
                proxy (str, optional): proxy configuration to use

                type (str, optional): type of corefiler (default 'cloud')
                cloud_type (str, optional): cloud type (default 's3')
                s3_type (str, optional): S3 type (default Service.S3TYPE_NAME)
                https (str, optional): 'yes' or 'no' to use HTTPS (default 'yes')
                crypto_mode (str, optional): crypto mode (default CBC-AES-256-HMAC-SHA-512)
                compress_mode (str, optional): compression mode (default LZ4)
                https_verify_mode (str, optional): DISABLED, OCSP, CRL, or OCSP_CRL
                remove_on_fail (bool, optional): remove the corefiler if the configuration does not finish
                existing_data (bool, optional): the bucket has existing data in it (defaults to False)

            Returns:
                key (dict): encryption key for the bucket if encryption is enabled

            Raises: vFXTConfigurationException
        '''
        xmlrpc = self.xmlrpc()
        if corefiler in self._xmlrpc_do(xmlrpc.corefiler.list):
            raise vFXTConfigurationException("Corefiler {} exists".format(corefiler))

        if not credential:
            log.debug("Looking up credential as none was specified")
            credential = self.service.authorize_bucket(self, bucketname, xmlrpc=xmlrpc)
            log.debug("Using credential {}".format(credential))

        # set proxy if provided
        if not proxy:
            if self.proxy:
                proxy = self.proxy.hostname

        data = {
            'type': options.get('type') or 'cloud',
            'cloudType': options.get('cloud_type') or self.service.COREFILER_TYPE,
            'bucket': bucketname,
            'cloudCredential': credential,
            'https': options.get('https') or 'yes',
            'sslVerifyMode': options.get('https_verify_mode') or 'OCSP_CRL',
            'compressMode': options.get('compress_mode') or 'LZ4',
            'cryptoMode': options.get('crypto_mode') or 'CBC-AES-256-HMAC-SHA-512',
            'proxy': proxy or '',
            'bucketContents': 'used' if options.get('existing_data', False) else 'empty',
        }

        if options.get('serverName'):
            data['serverName'] = options.get('serverName')

        if data['cloudType'] == 's3':
            data['s3Type'] = options.get('s3_type') or self.service.S3TYPE_NAME

        log.info("Creating corefiler {}".format(corefiler))
        log.debug("corefiler.createCloudFiler options {}".format(data))

        activity = None
        retries = self.LICENSE_TIMEOUT
        while True:
            try:
                activity = xmlrpc.corefiler.createCloudFiler(corefiler, data)
                break
            except xmlrpclib_Fault as e:
                # These errors are non-fatal:
                    # This cluster is not licensed for cloud core filers.  A FlashCloud license is required.
                    # Cannot modify while a group of nodes is joining
                allowed_errors = ['a group of nodes is joining', 'A FlashCloud license is required']
                if not any([_ in e.faultString for _ in allowed_errors]):
                    raise
                log.debug("Waiting for error to clear: {}".format(e))
                if retries == 0:
                    raise
                retries -= 1
                self._sleep()
        self._xmlrpc_wait_for_activity(activity, "Failed to create corefiler {}".format(corefiler), retries=self.service.WAIT_FOR_SUCCESS)

        def _cleanup():
            # try and remove it
            if options.get('remove_on_fail'):
                try:
                    self.remove_corefiler(corefiler)
                except Exception as e:
                    log.error("Failed to remove corefiler {}: {}".format(corefiler, e))

        # we have to wait for the corefiler to show up... may be blocked by other things
        # going on after corefiler.createCloudFiler completes.
        retries = self.service.WAIT_FOR_SUCCESS
        while True:
            try:
                if corefiler in xmlrpc.corefiler.list():
                    break
            except xmlrpclib_Fault as xfe:
                log.debug(xfe)
                xmlrpc = self.xmlrpc()
            log.debug("Waiting for corefiler to show up")
            if retries == 0:
                _cleanup()
                raise vFXTConfigurationException('Failed to create corefiler {}: Not found'.format(corefiler))
            if retries % 10 == 0:
                self._log_conditions(xmlrpc)
            retries -= 1
            self._sleep()

        if options.get('crypto_mode') != 'DISABLED':
            if not master_password:
                log.info("Generating master key for {} using the admin pass phrase".format(corefiler))
                master_password = self.admin_password
            else:
                log.info("Generating master key for {} using the specified pass phrase".format(corefiler))

            retries = self.service.XMLRPC_RETRIES
            while True:
                try:
                    key = xmlrpc.corefiler.generateMasterKey(corefiler, master_password)
                    if 'keyId' in key and 'recoveryFile' in key:
                        break
                except Exception as e:
                    log.debug(e)
                if retries == 0:
                    _cleanup()
                    raise vFXTConfigurationException('Failed to generate master key for {}: {}'.format(corefiler, e))
                retries -= 1
                self._sleep()

            log.info("Activating master key {} (signature {}) for {}".format(key['keyId'], key['signature'], corefiler))
            response = self._xmlrpc_do(xmlrpc.corefiler.activateMasterKey, corefiler, key['keyId'], key['recoveryFile'])
            if response != 'success':
                _cleanup()
                raise vFXTConfigurationException('Failed to activate master key for {}: {}'.format(corefiler, response))

            return key

    def attach_corefiler(self, corefiler, networkname, **options):
        '''Attach a Corefiler

            Arguments:
                corefiler (str): name of the corefiler to create
                networkname (str): network reachable name/address of the filer
                retries (int, optional): defaults to ServiceBase.WAIT_FOR_SUCCESS
                remove_on_fail (bool, optional): remove if any post create check fails
                ignore_warnings (bool, optional): ignore warnings during create, defaults to False
                nfs_type (str, optional): specify the type of the NFS server

                nfs_type can be one of:
                  NetappNonClustered
                  NetappClustered
                  EmcIsilon
                  Other (default)

            Raises: vFXTConfigurationException
        '''
        if corefiler in self._xmlrpc_do(self.xmlrpc().corefiler.list):
            raise vFXTConfigurationException("Corefiler {} exists".format(corefiler))

        try:
            socket.gethostbyname(networkname)
        except Exception as e:
            raise vFXTConfigurationException("Unknown host {}: {}".format(corefiler, e))

        ignore_warnings = options.get('ignore_warnings') or False
        create_options = {
            'filerClass': options.get('nfs_type') or 'Other'
        }

        log.info("Creating corefiler {}".format(corefiler))
        activity = self._xmlrpc_do(self.xmlrpc().corefiler.create, corefiler, networkname, ignore_warnings, create_options)
        self._xmlrpc_wait_for_activity(activity, "Failed to create corefiler {}".format(corefiler), retries=self.service.WAIT_FOR_SUCCESS)

        # we have to wait for the corefiler to show up... may be blocked by other things
        # going on after corefiler.createCloudFiler completes.
        retries = options.get('retries') or self.service.WAIT_FOR_SUCCESS
        xmlrpc = self.xmlrpc()
        while True:
            try:
                if corefiler in xmlrpc.corefiler.list():
                    break
            except Exception: pass
            log.debug("Waiting for corefiler to show up")
            if retries == 0:
                if options.get('remove_on_fail'):
                    try:
                        self.remove_corefiler(corefiler)
                    except Exception as e:
                        log.error("Failed to remove corefiler {}: {}".format(corefiler, e))
                raise vFXTConfigurationException('Failed to create corefiler {}'.format(corefiler))
            if retries % 10 == 0:
                self._log_conditions(xmlrpc)
            retries -= 1
            self._sleep()

    def remove_corefiler(self, corefiler):
        '''Remove a corefiler

            Arguments:
                corefiler (str): the name of the corefiler

            Raises vFXTConfigurationException
        '''
        try:
            xmlrpc = self.xmlrpc()
            self._enable_maintenance_api(xmlrpc)
            activity =  self._xmlrpc_do(xmlrpc.corefiler.remove, corefiler)
            self._xmlrpc_wait_for_activity(activity, "Failed to remove corefiler {}".format(corefiler))
        except vFXTConfigurationException as e:
            log.debug(e)
            raise
        except Exception as e:
            raise vFXTConfigurationException(e)

    def flush_corefiler(self, corefiler):
        '''Flush a corefiler

            Arguments:
                corefiler (str): the name of the corefiler

            Raises vFXTConfigurationException
        '''
        try:
            xmlrpc = self.xmlrpc()
            self._enable_maintenance_api(xmlrpc)
            activity = self._xmlrpc_do(xmlrpc.corefiler.flush, corefiler)
            self._xmlrpc_wait_for_activity(activity, "Failed to flush corefiler {}".format(corefiler))
        except xmlrpclib_Fault as e:
            if int(e.faultCode) != 108: # Method not supported
                raise vFXTConfigurationException(e)
        except Exception as e:
            raise vFXTConfigurationException(e)

    def add_vserver(self, name, size=0, netmask=None, start_address=None, end_address=None, home_addresses=False, retries=ServiceBase.WAIT_FOR_OPERATION):
        '''Add a Vserver

            Arguments:
                name (str): name of the vserver
                size (int, optional): size of the vserver address range (defaults to cluster size)
                netmask (str, optional): Network mask for the vserver range
                start_address (str, optional): Starting network address for the vserver range
                end_address (str, optional): Ending network address for the vserver range
                retries (int, optional): number of retries

            Calling with netmask, start_address, and end_address will define the vserver with
            those values.

            Otherwise, calling with or without a size leads to the addresses being determined via
            get_available_addresses().
        '''
        if name in self._xmlrpc_do(self.xmlrpc().vserver.list):
            raise vFXTConfigurationException("Vserver '{}' exists".format(name))

        if not all([netmask, start_address, end_address]):
            if any([netmask, start_address, end_address]):
                log.warn("Ignoring address configuration because missing one of {}(start), {}(end), or {}(netmask)".format(start_address, end_address, netmask))
            in_use_addrs        = self.in_use_addresses()
            vserver_ips, netmask = self.service.get_available_addresses(count=size or len(self.nodes), contiguous=True, in_use=in_use_addrs)
            start_address       = vserver_ips[0]
            end_address         = vserver_ips[-1]
        else:
            # Validate
            vserver_ips = Cidr.expand_address_range(start_address, end_address)
            if len(vserver_ips) < len(self.nodes):
                log.warn("Adding vserver address range without enough addresses for all nodes")

        log.info("Creating vserver {} ({}-{}/{})".format(name, start_address, end_address, netmask))
        activity = self._xmlrpc_do(self.xmlrpc().vserver.create, name, {'firstIP': start_address, 'lastIP': end_address, 'netmask': netmask})
        self._xmlrpc_wait_for_activity(activity, "Failed to create vserver {}".format(name), retries=retries)

        # wait for vserver to become available
        vserver_retries = retries
        log.debug("Waiting for vserver '{}' to show up".format(name))
        while True:
            try:
                if name in self._xmlrpc_do(self.xmlrpc().vserver.list):
                    break
                if vserver_retries % 10 == 0:
                    log.debug("{} not yet configured".format(name))
            except Exception as e:
                log.debug(e)
            vserver_retries -= 1
            if vserver_retries == 0:
                raise vFXTConfigurationException("Timed out waiting for vserver '{}' to show up.".format(name))
            self._sleep()

        if home_addresses:
            self.vserver_home_addresses(name)

    def add_vserver_junction(self, vserver, corefiler, path=None, export='/', subdir=None, retries=ServiceBase.EXTENDED_XMLRPC_RETRIES):
        '''Add a Junction to a Vserver

            Arguments:
                vserver (str): name of the vserver
                corefiler (str): name of the corefiler
                path (str, optional): path of the junction (default /{corefiler})
                export (str, optional): export path (default /)
                subdir (str, optional): subdirectory within the export
                retries (int, optional): number of retries

            Raises: vFXTConfigurationException
        '''
        if not path:
            path = '/{}'.format(corefiler)
        if not path.startswith('/'):
            #raise vFXTConfigurationException("Junction path must start with /: {}".format(path))
            path = '/{}'.format(path)

        advanced = {}
        if subdir:
            advanced['subdir'] = subdir

        log.info("Waiting for corefiler exports to show up")
        op_retries = self.service.WAIT_FOR_SUCCESS
        while True:
            try:
                exports = self._xmlrpc_do(self.xmlrpc().nfs.listExports, vserver, corefiler)
                if exports:
                    break
            except Exception as e:
                log.debug(e)
            if op_retries == 0:
                raise vFXTConfigurationException("Timed out waiting for {} exports".format(corefiler))
            if op_retries % 10 == 0:
                self._log_conditions(self.xmlrpc())
            op_retries -= 1
            self._sleep()

        log.info("Creating junction {} to {} for vserver {}".format(path, corefiler, vserver))
        try:
            activity = self._xmlrpc_do(self.xmlrpc().vserver.addJunction, vserver, path, corefiler, export, advanced, _xmlrpc_do_retries=retries)
            self._xmlrpc_wait_for_activity(activity, "Failed to add junction to {}".format(vserver))
        except Exception as e:
            raise vFXTConfigurationException("Failed to add junction to {}: {}".format(vserver, e))
        log.debug("Junctioned vserver {} with corefiler {} (path {}, export {})".format(vserver, corefiler, path, export))

    def wait_for_nodes_to_join(self, retries=ServiceBase.WAIT_FOR_HEALTH_CHECKS, xmlrpc=None):
        '''This performs a check that the cluster configuration matches the
            nodes in the object, otherwise it will wait

            Arguments:
                retries (int): number of retries (default 600)
                xmlrpc (xmlrpcClt, optional): xmlrpc client

            Raises: vFXTConfigurationException
        '''
        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc
        expected = len(self.nodes)
        if expected > len(self._xmlrpc_do(xmlrpc.node.list)):
            log.info("Waiting for all nodes to join")

            start_time = int(time.time())
            node_addresses = [n.ip() for n in self.nodes]
            while True:
                found = 1 # have to find one node at least
                try:
                    found = len(self._xmlrpc_do(xmlrpc.node.list))
                    if expected == found:
                        log.debug("Found {}".format(found))
                        break
                except Exception as e:
                    log.debug("Error getting node list: {}".format(e))

                try:
                    # if nodes are upgrading, delay the retries..  unjoined node status include:
                    # 'joining: started'
                    # 'joining: almost done'
                    # 'joining: upgrade the image'
                    # 'joining: switch to the new image'
                    unjoined_status = [_['status'] for _ in self._xmlrpc_do(xmlrpc.node.listUnconfiguredNodes) if _['address'] in node_addresses]
                    if any(['image' in _ for _ in unjoined_status]):
                        log.debug("Waiting for image upgrade to finish: {}".format(unjoined_status))
                        start_time = int(time.time())
                        continue
                except Exception as e:
                    log.debug("Failed to check unconfigured node status: {}".format(e))

                # for connectivity problems... we end up waiting a long time for
                # timeouts on the xmlrpc connection... so if we are taking too long
                # we should bail
                duration = int(time.time()) - start_time
                taking_too_long = duration > int(retries * 1.5)

                if retries == 0 or taking_too_long:
                    diff = expected - found
                    raise vFXTConfigurationException("Timed out waiting for {} node(s) to join.".format(diff))
                retries -= 1
                if retries % 10 == 0:
                    log.debug("Found {}, expected {}".format(found, expected))
                    self._log_conditions(xmlrpc=xmlrpc)
                self._sleep()
        log.info("All nodes have joined the cluster.")

    def enable_ha(self, retries=ServiceBase.XMLRPC_RETRIES, xmlrpc=None):
        '''Enable HA on the cluster

            Arguments:
                retries (int, optional): number of retries
                xmlrpc (xmlrpcClt, optional): xmlrpc client

            Raises: vFXTConfigurationException
        '''
        log.info("Enabling HA mode")
        try:
            xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc
            status = self._xmlrpc_do(xmlrpc.cluster.enableHA, _xmlrpc_do_retries=retries)
            if status != 'success':
                raise vFXTConfigurationException(status)
        except Exception as ha_e:
            raise vFXTConfigurationException("Failed to enable HA: {}".format(ha_e))

    def rebalance_directory_managers(self, retries=ServiceBase.XMLRPC_RETRIES):
        '''Call rebalanceDirManagers via XMLRPC

            Arguments:
                retries (int): number of retries

            Raises: vFXTConfigurationException
        '''
        xmlrpc = self.xmlrpc()
        self._enable_maintenance_api(xmlrpc)
        log.info("Rebalancing directory managers")
        try:
            status = self._xmlrpc_do(xmlrpc.maint.rebalanceDirManagers, _xmlrpc_do_retries=retries)
            if status != 'success':
                raise vFXTConfigurationException(status)
        except xmlrpclib_Fault as e:
            # AVERE_EINVAL, not needed or already in progress
            if int(e.faultCode) == 103: #pylint: disable=no-member
                return
            raise vFXTStatusFailure("Waiting for cluster rebalance failed: {}".format(e))
        except Exception as e:
            raise vFXTStatusFailure("Waiting for cluster rebalance failed: {}".format(e))

    def first_node_configuration(self):
        '''Basic configuration for the first cluster node
        '''
        if not self.mgmt_ip:
            raise vFXTConfigurationException("Cannot configure a cluster without a management address")
        log.info("Waiting for remote API connectivity")
        xmlrpc = None
        try:
            xmlrpc = self.xmlrpc(retries=ServiceBase.WAIT_FOR_INITIAL_CONNECTION) #pylint: disable=unused-variable
        except Exception as e:
            self.first_node_error = e
            raise

        self.set_default_proxy(xmlrpc=xmlrpc)

        if self.trace_level:
            log.info("Setting trace {}".format(self.trace_level))
            support_opts = {'rollingTrace': 'yes', 'traceLevel': self.trace_level}
            try:
                response = self._xmlrpc_do(xmlrpc.support.modify, support_opts)
                if response[0] != 'success':
                    self.first_node_error = vFXTConfigurationException(response)
                    raise self.first_node_error #pylint: disable=raising-bad-type
            except Exception as e:
                log.error("Failed to configure trace options: {}".format(e))

        if self.timezone:
            log.info("Setting timezone to {}".format(self.timezone))
            response = self._xmlrpc_do(xmlrpc.cluster.modify, {'timezone': self.timezone})
            if response != 'success':
                self.first_node_error = vFXTConfigurationException(response)
                raise self.first_node_error #pylint: disable=raising-bad-type

        # try and enable HA early if we have support in the AvereOS release for single node
        try:
            try:
                self.enable_ha(xmlrpc=xmlrpc)
            except Exception as e:
                log.debug("Failed to enable early HA, will retry later: {}".format(e))
        except Exception as e:
            log.debug("Failed during final first node configuration: {}".format(e))
            self.first_node_error = vFXTConfigurationException(e)
            raise self.first_node_error #pylint: disable=raising-bad-type

    def set_default_proxy(self, name=None, xmlrpc=None):
        '''Set the default cluster proxy configuration

            Arguments:
                name (str, optional): proxy name (defaults to proxy hostname)
                xmlrpc (xmlrpcClt, optional): xmlrpc client
        '''
        if not self.proxy:
            log.debug("Skipping proxy configuration")
            return
        name   = name or self.proxy.hostname
        if not name or not self.proxy.geturl():
            raise vFXTConfigurationException("Unable to create proxy configuration: Bad proxy host")

        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc
        body = {'url': self.proxy.geturl(), 'user': self.proxy.username or '', 'password': self.proxy.password or ''}
        if name not in self._xmlrpc_do(xmlrpc.cluster.listProxyConfigs):
            log.info("Setting proxy configuration")
            try:
                response = self._xmlrpc_do(xmlrpc.cluster.createProxyConfig, name, body)
                if response != 'success':
                    raise vFXTConfigurationException(response)
            except Exception as e:
                raise vFXTConfigurationException("Unable to create proxy configuration: {}".format(e))

        try:
            response = self._xmlrpc_do(xmlrpc.cluster.modify, {'proxy': name})
            if response != 'success':
                raise vFXTConfigurationException(response)
        except Exception as e:
            raise vFXTConfigurationException("Unable to configure cluster proxy configuration: {}".format(e))

    def allow_node_join(self, enable=True, retries=ServiceBase.WAIT_FOR_HEALTH_CHECKS, xmlrpc=None): #pylint: disable=unused-argument
        '''Enable created nodes to join

            Arguments:
                enable (bool, optional): Allow nodes to join
                retries (int): number of retries (default 600)
                xmlrpc (xmlrpcClt, optional): xmlrpc client
        '''
        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc

        def _compat_allow_node_join(enable, xmlrpc):
            setting = 'yes' if enable else 'no'
            log.debug("_compat_allow_node_join setting allowAllNodesToJoin to {}".format(setting))
            response = self._xmlrpc_do(xmlrpc.cluster.modify, {'allowAllNodesToJoin': setting})
            if response != 'success':
                raise vFXTConfigurationException("Failed to update allow node join configuration: {}".format(response))

        if not enable:
            _compat_allow_node_join(enable, xmlrpc)
            return

        # we have to accumulate all of the nodes we expect to see in node.listUnconfiguredNodes
        node_addresses = [_.ip() for _ in self.nodes]
        node_count = len(node_addresses)
        joined_count = len(self._xmlrpc_do(xmlrpc.node.list))
        expected_unjoined_count = node_count - joined_count
        unjoined = []

        if not expected_unjoined_count:
            log.debug("Nodes joined on their own")
            return

        log.info("Waiting for {} nodes to show up and ask to join cluster".format(expected_unjoined_count))
        start_time = int(time.time())
        op_retries = retries
        while True:
            unjoined_count = 0
            try:
                unjoined = [_ for _ in self._xmlrpc_do(xmlrpc.node.listUnconfiguredNodes) if _['address'] in node_addresses]
                unjoined_count = len(unjoined)
                if unjoined_count == expected_unjoined_count:
                    break
            except Exception as e:
                log.debug("Failed to check unconfigured node status: {}".format(e))

            try:
                if len(self._xmlrpc_do(xmlrpc.node.list)) == node_count:
                    log.debug("Nodes joined on their own")
                    return
            except Exception as e:
                log.debug("Failed to check joined node status: {}".format(e))

            # either we run out of retries or we take too long
            duration = int(time.time()) - start_time
            taking_too_long = duration > int(retries * 1.5)
            if op_retries == 0 or taking_too_long:
                diff = expected_unjoined_count - unjoined_count
                raise vFXTConfigurationException("Timed out waiting for {} node(s) to come up.".format(diff))
            if op_retries % 10 == 0:
                unjoined_names = ', '.join([_['name'] for _ in unjoined])
                log.debug("Found {} ({}), expected {}".format(unjoined_count, unjoined_names, expected_unjoined_count))
                self._log_conditions(xmlrpc=xmlrpc)
            op_retries -= 1
            self._sleep()

        # once we have them, call node.allowToJoin with our nodes in one group
        node_names = [_['name'] for _ in unjoined]
        log.info("Setting allow join for {} nodes".format(expected_unjoined_count))
        log.debug(','.join(node_names))
        try:
            activity = self._xmlrpc_do(xmlrpc.node.allowToJoin, ','.join(node_names), False)
            self._xmlrpc_wait_for_activity(activity, '"Failed to allow multiple node joins', retries=retries)
            return
        except xmlrpclib_Fault as e:
            # older releases cannot accept comma delimited node names
            if not any([_ in e.faultString for _ in ['Cannot find node', 'Cannot join the node']]):
                raise
        # try old way
        log.info("Setting node join policy")
        _compat_allow_node_join(enable, xmlrpc)

    def refresh(self):
        '''Refresh instance data of cluster nodes from the backend service'''
        for n in self.nodes:
            n.refresh()

    def reload(self):
        '''Reload all cluster information'''
        if self.is_on(): # reread configuration, uses xmlrpc so must be on
            self.load_cluster_information()
        else:
            self.refresh()

    def export(self):
        '''Export the cluster object in an easy to serialize format'''
        return {
            'name': self.name,
            'mgmt_ip': self.mgmt_ip,
            'admin_password': self.admin_password,
            'nodes': [n.instance_id for n in self.nodes]
        }

    def _sleep(self, duration=None):
        '''General sleep handling'''
        time.sleep(duration or self.service.POLLTIME)

    @classmethod
    def valid_cluster_name(cls, name):
        '''Validate the cluster name

            Returns: bool
        '''
        name_len = len(name)
        if name_len < 1 or name_len > 128:
            return False
        if re.search('^[a-z]([-a-z0-9]*[a-z0-9])?$', name):
            return True
        return False

    def in_use_addresses(self, category='all', xmlrpc=None):
        '''Get in use addresses from the cluster

            Arguments:
                category (str): all (default), mgmt, vserver, cluster
                xmlrpc (xmlrpcClt, optional): xmlrpc client
        '''
        addresses = set()
        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc

        if category in ['all', 'mgmt']:
            addresses.update([self._xmlrpc_do(xmlrpc.cluster.get)['mgmtIP']['IP']])

        if category in ['all', 'vserver']:
            for vs in self._xmlrpc_do(xmlrpc.vserver.list):
                data = self._xmlrpc_do(xmlrpc.vserver.get, vs)
                for client_range in data[vs]['clientFacingIPs']:
                    first = client_range['firstIP']
                    last  = client_range['lastIP']
                    range_addrs = Cidr.expand_address_range(first, last)
                    addresses.update(range_addrs)

        if category in ['all', 'cluster']:
            data = self._xmlrpc_do(xmlrpc.cluster.get)
            for cluster_range in data['clusterIPs']:
                first = cluster_range['firstIP']
                last  = cluster_range['lastIP']
                range_addrs = Cidr.expand_address_range(first, last)
                addresses.update(range_addrs)

        return list(addresses)

    def set_node_naming_policy(self, xmlrpc=None):
        '''Rename nodes internally and set the default node prefix

            This sets the node names internally to match the service instance
            names.  This also sets the node prefix to be the cluster name.

            Arguments:
                xmlrpc (xmlrpcClt, optional): xmlrpc client
        '''
        if not self.nodes:
            log.debug("No nodes to rename, skipping")
            return
        if not self.node_rename:
            log.debug("Skipping node naming configuration")
            return

        node_ip_map = {ip: n.name() for n in self.nodes for ip in n.in_use_addresses()}

        # rename nodes with cluster prefix
        log.info("Setting node naming policy")

        # first pass, rename new mismatched nodes to their node id
        retries = ServiceBase.XMLRPC_RETRIES
        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc
        while True:
            try:
                node_names = self._xmlrpc_do(xmlrpc.node.list)
                nodes = [self._xmlrpc_do(xmlrpc.node.get, _).values()[0] for _ in node_names]
                for node in nodes:
                    node_name = node_ip_map.get(node['primaryClusterIP']['IP'], None)
                    if node_name and node_name != node['name'] and node_name in node_names:
                        log.debug("Renaming new node {} -> {}".format(node['name'], node['id']))
                        self._xmlrpc_do(xmlrpc.node.rename, node['name'], node['id'])
                break
            except Exception as e:
                log.debug(e)
                if retries == 0:
                    log.error("Failed to rename nodes: {}".format(e))
                    break
                retries -= 1

        # second pass, rename all nodes to their instance names
        retries = ServiceBase.XMLRPC_RETRIES
        while True:
            try:
                node_names = self._xmlrpc_do(xmlrpc.node.list)
                nodes = [self._xmlrpc_do(xmlrpc.node.get, _).values()[0] for _ in node_names]
                for node in nodes:
                    node_name = node_ip_map.get(node['primaryClusterIP']['IP'], None)
                    if node_name and node_name != node['name'] and node_name not in node_names:
                        log.debug("Renaming node {} -> {}".format(node['name'], node_name))
                        self._xmlrpc_do(xmlrpc.node.rename, node['name'], node_name)
                break
            except Exception as e:
                log.debug(e)
                if retries == 0:
                    log.error("Failed to rename nodes: {}".format(e))
                    break
                retries -= 1

    def vserver_home_addresses(self, vservers=None, xmlrpc=None):
        '''Home the addresses of the vserver across the nodes

            Arguments:
                vservers (list, optional): list of vservers to home (otherwise all vservers)
                xmlrpc (xmlrpcClt, optional): xmlrpc client
        '''
        xmlrpc = self.xmlrpc() if xmlrpc is None else xmlrpc
        vservers = vservers or xmlrpc.vserver.list()
        if not isinstance(vservers, list):
            vservers = [vservers]

        nodes = itertools.cycle(sorted(xmlrpc.node.list()))
        for vserver in vservers:
            home_cfg = self._xmlrpc_do(xmlrpc.vserver.listClientIPHomes, vserver)
            # if all addresses are already homed, bail
            if [_ for _ in home_cfg if _['home'] != 'None']:
                log.debug("Refusing to override existing home configuration")
                continue

            # get the address ranges from our vserver
            vserver_data = xmlrpc.vserver.get(vserver)[vserver]
            vifs = set()
            for address_range in vserver_data['clientFacingIPs']:
                vifs.update(Cidr.expand_address_range(address_range['firstIP'], address_range['lastIP']))
            # sort numerically
            vifs = [Cidr.to_address(_) for _ in sorted([Cidr.from_address(_) for _ in vifs])]
            # build mapping table
            mappings = {vif: nodes.next() for vif in vifs}

            old_mappings = {_['ip']: _['current'] for _ in home_cfg}
            if not [_ for _ in mappings.keys() if mappings[_] != old_mappings.get(_)]:
                log.debug("Address home configuration is up to date for vserver '{}'".format(vserver))
                continue

            log.debug("Setting up addresses home configuration for vserver '{}': {}".format(vserver, mappings))
            retries = self.service.EXTENDED_XMLRPC_RETRIES
            while True:
                try:
                    activity = self._xmlrpc_do(xmlrpc.vserver.modifyClientIPHomes, vserver, mappings)
                    self._xmlrpc_wait_for_activity(activity, "Failed to rebalance vserver {} addresses".format(vserver))
                    break
                except Exception as e:
                    log.debug(e)
                    if retries == 0:
                        raise
                retries -= 1
