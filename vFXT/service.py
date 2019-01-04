# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
'''Service commons'''

import re
import os
import urllib2
import filecmp
import logging
import random
import urlparse
import socket
import threading
import json

class vFXTServiceTimeout(Exception): pass
class vFXTServiceConnectionFailure(Exception): pass
class vFXTServiceFailure(Exception): pass
class vFXTServiceMetaDataFailure(Exception): pass
class vFXTConfigurationException(Exception): pass
class vFXTCreateFailure(Exception): pass
class vFXTStatusFailure(Exception): pass
class vFXTConnectionFailure(Exception): pass
class vFXTNodeExistsException(Exception): pass

CONNECTION_TIMEOUT = 10
MAX_ERRORTIME = 30
DNS_TIMEOUT = 5.0

class ShelveErrors(dict):
    '''simple dict class with __str__ suitable for an instance tag'''
    def __init__(self, s=None): # optional init with str in k:v;k:v format
        if s:
            try:
                self.update( dict([e.split(':') for e in s.split(';')]) )
            except Exception:
                pass
    def __str__(self): # return k:v;k:v format
        return ";".join(["{}:{}".format(k, v) for k, v in self.iteritems()])

def backoff(counter, max_backoff=MAX_ERRORTIME):
    '''Return an exponential backoff time based on a provided counter

        Arguments:
            counter (int): incrementing value
            max_backoff (int): maximum backoff value (defaults to vFXT.service.MAX_ERRORTIME)
    '''
    return min(max_backoff, (2**counter) + (random.randint(0, 1000) / 1000.0))

def validate_proxy(proxy_uri):
    '''Validate the proxy URI

        Arguments:
            proxy_uri (str): http://[<user>[:<pass>]@]<host>[:<port>]

        This returns a urlparse.ParseResult object
    '''
    try:
        proxy = urlparse.urlparse(proxy_uri)
        if not proxy.hostname:
            raise vFXTConfigurationException("Invalid proxy: {}".format(proxy_uri))
        return proxy
    except vFXTConfigurationException:
        raise

def gethostbyname(host, timeout=DNS_TIMEOUT):
    '''Local gethostbyname that uses dns.resolver if available for fast timeouts
        Arguments:
            host (str): host name to resolve
            timeout (float): resolution timeout (defaults to vFXT.service.DNS_TIMEOUT)

        Raises: socket.gaierror
    '''
    try:
        from dns.resolver import Resolver
        import dns.inet
        r = Resolver()
        r.timeout = r.lifetime = timeout

        # if this is an address, return ok
        try:
            addr = dns.inet.inet_pton(dns.inet.af_for_address(host), host)
            if addr:
                return host
        except Exception: pass

        try:
            return r.query(host)[0].to_text()
        except Exception as e:
            raise socket.gaierror(e)
    except ImportError:
        return socket.gethostbyname(host)

def load_defaults(service):
    try:
        default_url = urlparse.urlparse(service.DEFAULTS_URL)
        if default_url.scheme not in ['http', 'https', 'file']:
            raise Exception("Invalid scheme: {}".format(default_url.scheme))

        proxy_handler = urllib2.ProxyHandler({})
        if service.proxy_uri:
            proxy_handler = urllib2.ProxyHandler({'http': service.proxy_uri, 'https': service.proxy_uri})

        opener = urllib2.build_opener(proxy_handler)
        req = urllib2.Request(service.DEFAULTS_URL)
        r = opener.open(req, timeout=CONNECTION_TIMEOUT)
        service.defaults = json.load(r)
    except Exception as e:
        logging.getLogger(service.__module__).error("Failed to load up to date defaults, using offline copy: {}".format(e))
        service.defaults = service.OFFLINE_DEFAULTS


class BarrierTimeout(Exception): pass
class Barrier(object):
    def __init__(self, size=1, timeout=None, errmsg="Timed out waiting for synchronization"):
        self.size = size
        self.counter = 0
        self.timeout = timeout
        self.errmsg = errmsg
        self.lock = threading.RLock()
        self.event = threading.Event()
    def wait(self, timeout=None):
        with self.lock:
            self.counter += 1
        if self.counter >= self.size:
            self.event.set()
        if not self.event.wait(timeout or self.timeout):
            raise BarrierTimeout(self.errmsg)


class ServiceBase(object):
    '''Basic service interface'''
    CLUSTER_NODE_NAME_RE = re.compile(r'^(.*?)\-([0-9]+)$')
    BUCKET_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{1,253}[a-zA-Z0-9]$') # no periods for S3 Transfer acceleration
    TOO_LONG_DNS_NAME_COMP_RE = re.compile(r'[-_a-z0-9]{64}')
    POLLTIME = 1
    WAIT_FOR_SUCCESS = 300
    WAIT_FOR_DESTROY = 600
    WAIT_FOR_START = WAIT_FOR_SUCCESS
    WAIT_FOR_RESTART = WAIT_FOR_SUCCESS
    WAIT_FOR_STOP = 600
    WAIT_FOR_STATUS = 120
    WAIT_FOR_OPERATION = 60
    WAIT_FOR_INITIAL_CONNECTION = 60
    WAIT_FOR_SERVICE_CHECKS = 600
    WAIT_FOR_HEALTH_CHECKS = 600
    WAIT_FOR_NFS_EXPORTS = 600
    WAIT_FOR_TELEMETRY = 600
    EXTENDED_XMLRPC_RETRIES = 120
    XMLRPC_RETRIES = 5
    CLOUD_API_RETRIES = 3
    ENDPOINT_TEST_HOSTS = []
    ALLOCATE_INSTANCE_ADDRESSES = False
    S3TYPE_NAME = None
    AUTO_LICENSE = False

    def __init__(self, *args, **kwargs): #pylint: disable=unused-argument
        self.defaults = {}
        self.local = threading.local()
        self.proxy_uri = None
        self.proxy = None
        self.source_address = None

    def connection_test(self):
        raise NotImplementedError()
    def connection(self):
        raise NotImplementedError()
    def check(self, percentage, instances):
        raise NotImplementedError()

    @classmethod
    def get_instance_data(cls, source_address=None):
        raise NotImplementedError()

    @classmethod
    def environment_init(cls, **kwargs):
        raise NotImplementedError()

    @classmethod
    def on_instance_init(cls, source_address=None, no_connection_test=False):
        raise NotImplementedError()

    def find_instances(self, search=None):
        raise NotImplementedError()
    def get_instances(self, instance_ids):
        raise NotImplementedError()
    def get_instance(self, instance_id):
        raise NotImplementedError()
    def wait_for_status(self, instance, status, retries=WAIT_FOR_STATUS):
        raise NotImplementedError()
    def wait_for_service_checks(self, instance, retries=WAIT_FOR_SERVICE_CHECKS):
        raise NotImplementedError()
    def stop(self, instance, wait=WAIT_FOR_STOP):
        raise NotImplementedError()
    def start(self, instance, wait=WAIT_FOR_START):
        raise NotImplementedError()
    def restart(self, instance, wait=WAIT_FOR_RESTART):
        raise NotImplementedError()
    def destroy(self, instance, wait=WAIT_FOR_DESTROY):
        raise NotImplementedError()
    def is_on(self, instance):
        raise NotImplementedError()
    def is_off(self, instance):
        raise NotImplementedError()
    def name(self, instance):
        raise NotImplementedError()
    def instance_id(self, instance):
        raise NotImplementedError()
    def ip(self, instance):
        raise NotImplementedError()
    def fqdn(self, instance):
        raise NotImplementedError()
    def status(self, instance):
        raise NotImplementedError()
    def refresh(self, instance):
        raise NotImplementedError()
    def can_stop(self, instance):
        raise NotImplementedError()

    def create_instance(self, machine_type, name, **options):
        raise NotImplementedError()
    def create_node(self, node_name, cfg, node_opts, instance_options):
        raise NotImplementedError()
    def create_cluster(self, cluster, **options):
        raise NotImplementedError()
    def post_destroy_cluster(self, cluster):
        raise NotImplementedError()
    def _add_cluster_nodes_setup(self, cluster, count, **options):
        '''Service specific customization prior to adding nodes'''
        pass
    def add_cluster_nodes(self, cluster, count, **options):
        raise NotImplementedError()
    def load_cluster_information(self, cluster, **options):
        raise NotImplementedError()

    def shelve(self, instance):
        raise NotImplementedError()
    def can_shelve(self, instance):
        raise NotImplementedError()
    def is_shelved(self, instance):
        raise NotImplementedError()
    def unshelve(self, instance, count_override=None, size_override=None, type_override=None):
        raise NotImplementedError()

    # storage/buckets

    def create_bucket(self, name):
        raise NotImplementedError()
    def delete_bucket(self, name):
        raise NotImplementedError()
    def authorize_bucket(self, cluster, name, retries=3, xmlrpc=None):
        raise NotImplementedError()

    # networking

    def get_default_router(self):
        raise NotImplementedError()
    def get_dns_servers(self):
        raise NotImplementedError()
    def get_ntp_servers(self):
        raise NotImplementedError()
    def get_available_addresses(self, count=1, contiguous=False, addr_range=None, in_use=None):
        raise NotImplementedError()
    def add_instance_address(self, instance, address, **options):
        raise NotImplementedError()
    def remove_instance_address(self, instance, address):
        raise NotImplementedError()
    def in_use_addresses(self, cidr_block):
        raise NotImplementedError()
    def instance_in_use_addresses(self, instance, category='all'):
        raise NotImplementedError()
    def export(self):
        raise NotImplementedError()

    def valid_bucketname(self, name):
        '''Validate the bucket name

            Returns: bool
        '''
        if self.BUCKET_NAME_RE.match(name) and not self.TOO_LONG_DNS_NAME_COMP_RE.search(name):
            return True
        return False

    def valid_instancename(self, name):
        '''Validate the instance name

            Returns: bool
        '''
        if len(name) > 255:
            return False
        return True

    def url_fetch(self, url, filename, chunksize=1024 * 1024):
        '''Retrieve the object from the URL, writing it to the passed in file location

            Arguments:
                url (str): proto://
                filename (str): name of destination file (absolute path)

            Returns: Nothing
            Raises: Exception
        '''
        sig_url      = url + '.sig'
        sig_filename = filename + '.sig'

        log = logging.getLogger(self.__module__)

        def _do_fetch(r, n):
            parsed_url = urlparse.urlparse(r)
            if parsed_url.scheme not in ['http', 'https', 'file']:
                raise Exception("Invalid scheme: {}".format(parsed_url.scheme))

            log.debug("Fetching {} to {}".format(r, n))
            remote      = urllib2.urlopen(r) # open first, before local file open
            destination = open(n, 'wb')
            while True:
                data = remote.read(chunksize)
                if not data:
                    break
                destination.write(data)
            destination.close()

        # check sig
        if os.access(sig_filename, os.F_OK) and os.access(filename, os.F_OK):
            sig_filename_tmp = sig_filename + '.tmp'
            try:
                _do_fetch(sig_url, sig_filename_tmp)
                sig_cmp = filecmp.cmp(sig_filename, sig_filename_tmp)
                os.unlink(sig_filename_tmp)
                if sig_cmp:
                    return # cached, no download necessary
            except Exception as e:
                log.debug(e)

        # fetch
        try:
            _do_fetch(sig_url, sig_filename)
        except Exception as e:
            log.debug(e)
        _do_fetch(url, filename)

    def set_proxy(self, proxy_uri):
        '''Set service proxy

            Arguments:
                proxy_uri (str): http://[<user>[:<pass>]@]<host>[:<port>]
        '''
        proxy          = validate_proxy(proxy_uri)
        self.proxy_uri = proxy_uri
        self.proxy     = proxy

    @classmethod
    def dns_check(cls, timeout=DNS_TIMEOUT):
        '''Verify name resolution to ENDPOINT_TEST_HOSTS

            Arguments:
                timeout (int, optional): defaults to vFXT.service.DNS_TIMEOUT
        '''
        try:
            for host in cls.ENDPOINT_TEST_HOSTS:
                gethostbyname(host, timeout)
        except socket.gaierror as e:
            raise vFXTConfigurationException("Failed to establish connection to service: {}".format(e))

    def get_current_instance(self):
        '''This is a helper to return the current backend instance object.

            This is only applicable when running on a cloud instance.
        '''
        return self.get_instance(self.get_current_instance_id()) #pylint: disable=no-member
    def get_current_instance_id(self):
        '''This is a helper to return the current backend instance identifier.

            This is only applicable when running on a cloud instance.
        '''
        if not self.on_instance: #pylint: disable=no-member
            raise vFXTConfigurationException("Not a cloud instance")
        return self.local.instance_data['service_id'] #pylint: disable=no-member
