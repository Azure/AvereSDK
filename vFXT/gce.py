# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
''' Abstraction for doing things on instances via Google Compute

Cookbook/examples:

# With JSON key file provided by Google service account
gce = vFXT.gce.Service(network, zone, key_file=path_to_json)
# or with a P12 key file provided by Google service account
gce = vFXT.gce.Service(network, zone, client_email, project, key_file=path_to_p12)
# or if on a GCE compute instance, we can autodetect service account and settings
gce = vFXT.gce.Service.on_instance_init()

# Connection factory, has a thread specific copy
connection = gce.connection()
compute_conn = gce.connection(connection_type='compute')
storage_conn = gce.connection(connection_type='storage')

instances = gce.find_instances('') # filter string
instances = gce.get_instances([])

instance = gce.get_instance('instance id')
gce.start(instance)
gce.stop(instance)
gce.restart(instance)
gce.destroy(instance)

gce.shelve(instance)
gce.unshelve(instance)

instance = gce.refresh(instance)

print gce.name(instance)
print gce.ip(instance)
print gce.fqdn(instance)
print gce.status(instance)

if gce.is_on(instance): pass
if gce.is_off(instance): pass
if gce.is_shelved(instance): pass

gce.wait_for_status(instance, gce.ON_STATUS, retries=gce.WAIT_FOR_STATUS)

gce.create_instance(machine_type, name, boot_disk_image, other_disks=None, **options)
gce.create_cluster(self, cluster, **options)

gce.create_bucket(name)
gce.delete_bucket(name)

gce.load_cluster_information(cluster)

ip_count = 12
ip_addresses, mask = gce.get_available_addresses(count=ip_count, contiguous=True)
gce.get_dns_servers()
gce.get_ntp_servers()
gce.get_default_router()

serializeme = gce.export()
newgce = vFXT.gce.Service(**serializeme)
'''

import httplib
import httplib2
import httplib2.socks
import ssl
import logging
import time
import threading
import Queue
import json
import socket
import re
import os
import uuid
import filecmp
from itertools import cycle

import googleapiclient.discovery
import oauth2client.client #pylint: disable=unused-import
import googleapiclient
logging.getLogger('googleapiclient').setLevel(logging.CRITICAL)

from vFXT.cidr import Cidr
from vFXT.serviceInstance import ServiceInstance
from vFXT.service import *

log = logging.getLogger(__name__)

class Service(ServiceBase):
    '''GCE Service backend'''
    ON_STATUS = "RUNNING"
    OFF_STATUS = "TERMINATED"
    NTP_SERVERS = ['169.254.169.254']
    DNS_SERVERS = ['169.254.169.254']
    GCE_URL = "https://www.googleapis.com/compute/v1/projects"
    GCE_INSTANCE_HOST = '169.254.169.254'
    CONTROL_ADDR = None
    MACHINE_DEFAULTS = {
        'f1-micro':         {'data_disk_size': 200, 'data_disk_type': 'pd-standard', 'data_disk_count': 1, 'node_count': 1, 'root_disk_type': 'pd-standard'},
        'g1-small':         {'data_disk_size': 200, 'data_disk_type': 'pd-standard', 'data_disk_count': 1, 'node_count': 1, 'root_disk_type': 'pd-standard'},
        'n1-highcpu-2':     {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 1, 'root_disk_type': 'pd-ssd'},
        'n1-highcpu-4':     {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highcpu-8':     {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highcpu-16':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highcpu-32':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highcpu-64':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highcpu-96':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-2':     {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 1, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-4':     {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-8':     {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-16':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-32':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-64':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-highmem-96':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-standard-1':    {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 1, 'root_disk_type': 'pd-ssd'},
        'n1-standard-2':    {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 1, 'root_disk_type': 'pd-ssd'},
        'n1-standard-4':    {'data_disk_size': 200, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-standard-8':    {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-standard-16':   {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-standard-32':   {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-standard-64':   {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'n1-standard-96':   {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
        'custom-6-40960':   {'data_disk_size': 250, 'data_disk_type': 'pd-ssd', 'data_disk_count': 1, 'node_count': 3, 'root_disk_type': 'pd-ssd'},
    }
    MACHINE_TYPES = MACHINE_DEFAULTS.keys()
    DEFAULTS_URL = "https://storage.googleapis.com/avere-dist/vfxtdefaults.json"
    DEFAULT_SCOPES = ['https://www.googleapis.com/auth/compute',
                    'https://www.googleapis.com/auth/devstorage.full_control',
                    'https://www.googleapis.com/auth/userinfo.email']
    S3TYPE_NAME = 'GOOGLE'
    COREFILER_TYPE = 's3'
    COREFILER_CRED_TYPE = 's3'
    INSTANCENAME_RE = re.compile(r'[a-z]([-a-z0-9]*[a-z0-9])?$')
    GSURL_RE = re.compile(r'gs://([^\/]*)/(.*)$')
    STORAGE_CLASSES = ['STANDARD', 'NEARLINE', 'DURABLE_REDUCED_AVAILABILITY', 'MULTI_REGIONAL', 'REGIONAL', 'COLDLINE']
    ENDPOINT_TEST_HOSTS = ['www.googleapis.com']
    DISABLE_SSL_CERTIFICATE_VALIDATION = False
    OFFLINE_DEFAULTS = {
      'version': '1',
      'clustermanager': {
        'maxNumNodes': 20,
        'instanceTypes': [ 'n1-highmem-8', 'n1-highmem-32' ],
        'cacheSizes': [
          {'label': '250-persistent-SSD', 'size': 250, 'type': 'pd-ssd'},
          {'label': '375-local-SSD', 'size': 375, 'type': 'local-ssd'},
          {'label': '1000-persistent-SSD', 'size': 1000, 'type': 'pd-ssd'},
          {'label': '1500-local-SSD', 'size': 1500, 'type': 'local-ssd'},
          {'label': '3000-local-SSD', 'size': 3000, 'type': 'local-ssd'},
          {'label': '4000-persistent-SSD', 'size': 4000, 'type': 'pd-ssd'},
          {'label': '8000-persistent-SSD', 'size': 8000, 'type': 'pd-ssd'}
        ]
      }
    }
    DEFAULT_CLUSTER_NETWORK_RANGE = '172.16.0.0/12'
    ALLOCATE_INSTANCE_ADDRESSES = True

    def __init__(self, network_id, zone, client_email=None, project_id=None,
                 key_file=None, key_data=None, access_token=None, s3_access_key=None,
                 s3_secret_access_key=None, private_range=None, proxy_uri=None,
                 no_connection_test=False, subnetwork_id=None, on_instance=False,
                 use_environment_for_auth=False, skip_load_defaults=False,
                 network_project_id=None, source_address=None):
        '''Constructor

            This performs an initial connection test and downloads the default
            data.

            Either a base64 encoded key string or the path to the service account
            P12/JSON key file must be provided.

            If the JSON key file is provided, client_email, project_id, and key are
            read from it.  Otherwise client_email and project_id must be specified.

            If an access token is provided, that will be used in place of the
            client_email + key/key_file.  This is only useful if running on a
            GCE instance.

            Arguments:
                network_id (str): network ID
                zone (str or []): one or more zones names

                client_email (str, optional): client email
                project_id (str, optional): project ID
                key_file (str, optional): file path to P12/JSON key file
                access_token (str, optional): existing access token

                private_range (str, optional): private address range (cidr)
                subnetwork_id (str, optional): subnetwork ID

                proxy_uri (str, optional): URI of proxy resource (e.g. http://user:pass@172.16.16.20:8080)

                no_connection_test (bool, optional): skip connection test
                skip_load_defaults (bool, optional): do not fetch defaults
                network_project_id (str, optional): Project ID that owns the network (if outside current project)
        '''
        super(Service, self).__init__()
        self.client_email = client_email
        self.key_file     = key_file
        self.key_data     = key_data
        self.access_token = access_token
        self.project_id   = project_id
        self.zones        = [zone] if isinstance(zone, basestring) else zone
        self.network_id   = network_id
        self.network_project_id = network_project_id
        self.s3_access_key        = s3_access_key
        self.s3_secret_access_key = s3_secret_access_key
        self.private_range = private_range
        self.subnetwork_id = subnetwork_id
        self.proxy_uri     = proxy_uri
        self.on_instance   = on_instance
        self.use_environment_for_auth = use_environment_for_auth
        self.source_address = source_address

        if not any([key_file, key_data, access_token, use_environment_for_auth]):
            raise vFXTConfigurationException("You must provide a keyfile or auth token")
        if self.key_data:
            try:
                self.client_email = self.key_data['client_email']
                self.project_id   = self.key_data['project_id']
            except KeyError:
                raise vFXTConfigurationException("Invalid key data: {}".format(self.key_data))
        elif self.key_file and self.key_file.endswith('.json'):
            with open(self.key_file, 'rb') as f:
                log.debug("Reading key data from {}".format(self.key_file))
                key_data = f.read()
                self.key_data = json.loads(key_data)
                try:
                    self.client_email = self.key_data['client_email']
                    self.project_id   = self.key_data['project_id']
                except KeyError:
                    raise vFXTConfigurationException("Invalid key file: {}".format(self.key_file))

        if not use_environment_for_auth:
            if not all([self.client_email, self.project_id]):
                raise vFXTConfigurationException("You must provide a keyfile or specify client_email and project_id")

        # emit third party library version information
        log.debug("Using googleapiclient version {}".format(googleapiclient.__version__))
        log.debug("Using oauth2client version {}".format(oauth2client.__version__))

        if self.proxy_uri:
            self.set_proxy(self.proxy_uri)

        # check if we have a Xpn host project
        try:
            self.network_project_id = self.network_project_id or self._get_network_project()
        except vFXTServiceTimeout as e:
            raise vFXTServiceConnectionFailure(e)

        if not no_connection_test:
            self.connection_test()

            if self.subnetwork_id:
                subnetwork_names = [_['name'] for _ in self._get_subnetworks()]
                if self.subnetwork_id not in subnetwork_names:
                    err = "Invalid subnetwork: {} (available {})".format(self.subnetwork_id, ','.join(subnetwork_names))
                    raise vFXTConfigurationException(err)

        if not skip_load_defaults:
            log.debug("Fetching defaults from {}".format(self.DEFAULTS_URL))
            load_defaults(self)

    @classmethod
    def get_instance_data(cls, source_address=None):
        '''Detect the instance data
            Arguments:
                source_address (str, optional): source address for data request

            This only works when running on a GCE instance.

            This is a service specific data structure.

            Well known keys that can be expected across services:
            machine_type (str): machine/instance type
            account_id (str): account identifier
            service_id (str): unique identifier for this host
            ssh_keys ([str]): ssh keys
            cluster_cfg (str): cluster configuration

            https://cloud.google.com/compute/docs/metadata
        '''
        if source_address:
            source_address = (source_address, 0)
        connection_host = cls.GCE_INSTANCE_HOST
        connection_port = httplib.HTTP_PORT

        conn          = httplib.HTTPConnection(connection_host, connection_port, source_address=source_address, timeout=CONNECTION_TIMEOUT)
        instance_data = {}
        headers       = {'Metadata-Flavor': 'Google'}
        attrs         = {
          'project-id': '/computeMetadata/v1/project/project-id',
          'numeric-project-id': '/computeMetadata/v1/project/numeric-project-id',
          'zone-id': '/computeMetadata/v1/instance/zone',
          'network-id': '/computeMetadata/v1/instance/network-interfaces/0/network',
          'ip': '/computeMetadata/v1/instance/network-interfaces/0/ip',
          'access-token': '/computeMetadata/v1/instance/service-accounts/default/token',
          'scopes': '/computeMetadata/v1/instance/service-accounts/default/scopes',
          'email': '/computeMetadata/v1/instance/service-accounts/default/email',
          'hostname': '/computeMetadata/v1/instance/hostname',
          'tags': '/computeMetadata/v1/instance/tags',
          'id': '/computeMetadata/v1/instance/id',
          'machine-type': '/computeMetadata/v1/instance/machine-type',
          'metadata_keys': '/computeMetadata/v1/instance/attributes/', # gives list b/c of trailing /
        }

        try:

            for k, v in attrs.iteritems():
                conn.request('GET', '{}'.format(v), headers=headers)
                response = conn.getresponse()
                if response.status == 200:
                    content = response.read()
                    try:
                        instance_data[k] = json.loads(content)
                    except ValueError as e:
                        instance_data[k] = content

            instance_data['metadata'] = {}
            for key in [_ for _ in instance_data['metadata_keys'].split('\n') if _]: # filter empty entries
                path = '{}{}'.format(attrs['metadata_keys'], key)
                conn.request('GET', '{}'.format(path), headers=headers)
                response = conn.getresponse()
                if response.status == 200:
                    content = response.read()
                    try:
                        instance_data['metadata'][key] = json.loads(content)
                    except ValueError as e:
                        instance_data['metadata'][key] = content

            if 'access-token' in instance_data:
                instance_data['access_token']  = instance_data['access-token']['access_token']
                instance_data['expires_in']    = instance_data['access-token']['expires_in']
                instance_data['token_expires'] = int(time.time()) + instance_data['expires_in'] - 120
            else: # try and support cloud shell
                # XXX right now this doesn't work... missing proper network-id (sets to default)
                try:
                    s = socket.socket()
                    s.connect(('localhost', int(os.getenv('DEVSHELL_CLIENT_PORT', '0'))))
                    s.sendall('2\n[]')
                    data = json.loads(s.recv(1024).split('\n')[1])
                    instance_data['email'] = data[0]
                    instance_data['project-id'] = data[1]
                    instance_data['access_token'] = data[2]
                    instance_data['token_expires'] = int(data[3]) - 120
                except Exception as e:
                    log.error('Failed to extract configuration for cloud shell: {}'.format(e))
                    raise

            instance_data['machine_type'] = instance_data['machine-type'].split('/')[-1]
            instance_data['account_id'] = instance_data['numeric-project-id']
            instance_data['service_id'] = instance_data['hostname'].split('.')[0]
            instance_data['ssh_keys'] = []
            if 'sshKeys' in instance_data['metadata']: # deprecated
                # prune username: from the key data
                instance_data['ssh_keys'] = [_.split(':')[-1] for _ in instance_data['metadata']['sshKeys'].split('\n')]
            if 'ssh-keys' in instance_data['metadata']:
                # prune username: from the key data
                instance_data['ssh_keys'].extend([_.split(':')[-1] for _ in instance_data['metadata']['ssh-keys'].split('\n')])

            instance_data['cluster_cfg'] = '' if 'cluster_cfg' not in instance_data['metadata'] \
                                        else instance_data['metadata']['cluster_cfg']\
                                            .replace('\\n', '\n').replace(' ', '\n').replace('_', '\n').replace('@', '=').decode('base64')
        except Exception as e:
            raise vFXTServiceMetaDataFailure('Unable to read instance metadata: {}'.format(e))
        finally:
            conn.close()

        return instance_data

    @classmethod
    def environment_init(cls, **kwargs):
        '''Init an GCE service object using the local environment credentials

            Arguments:
                **kwargs: arguments passed through to __init__
        '''
        kwargs['use_environment_for_auth'] = True
        return Service(**kwargs)

    @classmethod
    def on_instance_init(cls, source_address=None, no_connection_test=False, proxy_uri=None, **kwargs):
        '''Init a GCE service object from instance metadata
            Arguments:
                source_address (str, optional): source address for data request
                no_connection_test (bool, optional): skip connection tests, defaults to False
                proxy_uri (str, optional): URI of proxy resource
                skip_load_defaults (bool, optional): do not fetch defaults

            This is only meant to be called on instance.  Otherwise will
            raise a vFXTConfigurationException exception.
        '''
        instance_data = cls.get_instance_data(source_address=source_address)
        log.debug('Read instance data: {}'.format(instance_data))

        if source_address:
            Service.CONTROL_ADDR = source_address

            class HTTPSConnectionFromSource(httplib2.HTTPSConnectionWithTimeout):
                """
                An override of httplib2's HTTPSConnectionWithTimeout that forces
                connections to come from our controlAddr.  __init__ is essentially
                a copy of the httplib2 version.
                """
                def __init__(self, host, port=None, key_file=None, cert_file=None, #pylint: disable=unused-argument
                             strict=None, timeout=None, proxy_info=None,
                             ca_certs=None, disable_ssl_certificate_validation=False, **other_kwargs):
                    log.debug("Making connection to {} from {}".format(host, Service.CONTROL_ADDR))
                    httplib.HTTPSConnection.__init__(self, host, port=port,
                                                     key_file=key_file,
                                                     cert_file=cert_file, strict=strict, timeout=timeout,
                                                     source_address=(Service.CONTROL_ADDR, 0))
                    self.timeout = timeout
                    self.proxy_info = proxy_info
                    if ca_certs is None:
                        ca_certs = httplib2.CA_CERTS
                    self.ca_certs = ca_certs
                    self.disable_ssl_certificate_validation = disable_ssl_certificate_validation

                def connect(self):
                    "Connect to a host on a given (SSL) port."
                    if self.proxy_info and self.proxy_info.isgood():
                        sock = httplib2.socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                        proxy_type, proxy_host, proxy_port, proxy_rdns, proxy_user, proxy_pass = self.proxy_info.astuple()
                        sock.setproxy(proxy_type, proxy_host, proxy_port, proxy_rdns, proxy_user, proxy_pass)
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                    if self.source_address:
                        sock.bind(self.source_address)
                    if self.timeout:
                        sock.settimeout(float(self.timeout))

                    sock.connect((self.host, self.port))
                    # XXX set ssl_version in ssl.wrap_socket call
                    self.sock = ssl.wrap_socket(sock, keyfile=self.key_file, certfile=self.cert_file)

            httplib2.SCHEME_TO_CONNECTION['https'] = HTTPSConnectionFromSource


        # check scopes for one of the following
        required_scopes = ['https://www.googleapis.com/auth/compute', 'https://www.googleapis.com/auth/cloud-platform']
        if not any([_ in required_scopes for _ in instance_data['scopes'].split('\n')]):
            raise vFXTConfigurationException("Compute R/W or Full Access required for this instance")

        try:
            project_id   = instance_data['project-id']
            zone_id      = instance_data['zone-id'].split('/')[-1]
            network_id   = instance_data['network-id'].split('/')[-1]
            network_project_id = instance_data['network-id'].split('/')[1]
            access_token = instance_data['access_token']
            client_email = instance_data['email']
            srv = Service(network_id=network_id, client_email=client_email,
                          project_id=project_id, zone=zone_id,
                          access_token=access_token, no_connection_test=no_connection_test,
                          proxy_uri=proxy_uri, on_instance=True, skip_load_defaults=kwargs.get('skip_load_defaults'),
                          network_project_id=network_project_id, source_address=source_address)
            srv.local.instance_data = instance_data
            region = srv._zone_to_region(zone_id)
            # translate our network project id into a name
            srv.network_project_id = srv._get_network()['selfLink'].split('/')[-4]
            # no subnetwork in metadata... figure out which subnetwork owns our address
            subnetworks = srv._get_subnetworks(region)
            if subnetworks:
                for subnetwork in subnetworks:
                    if Cidr(subnetwork['ipCidrRange']).contains(instance_data['ip']):
                        srv.subnetwork_id = subnetwork['name']
                if not srv.subnetwork_id:
                    srv.subnetwork_id = subnetworks[0]['name']
            return srv
        except (vFXTServiceFailure, vFXTServiceConnectionFailure) as e:
            raise
        except Exception as e:
            raise vFXTConfigurationException(e)

    def connection_test(self):
        '''Connection test

            Raises: vFXTConfigurationException
        '''
        log.debug("Performing connection test")

        try:
            if not self.proxy: # proxy environments may block outgoing name resolution
                self.dns_check()

            conn = self.connection(retries=0)
            resp = conn.projects().get(project=self.project_id).execute()
            for q in resp['quotas']:
                if q['usage'] / q['limit'] > 0.9:
                    log.warn("QUOTA ALERT: Using {} of {} {}".format(int(q['usage']), int(q['limit']), q['metric']))
        except Exception as e:
            if isinstance(e, IOError):
                log.exception(e)
            raise vFXTServiceConnectionFailure("Failed to establish connection to service: {}".format(e))

    def check(self, percentage=0.6, instances=0, machine_type=None, data_disk_type=None, data_disk_size=None, data_disk_count=None):
        '''Check quotas and API access

            Arguments:
            percentage (float, optional): percentage as a decimal
            instances (int, optional): Number of planned for instances to account for
            machine_type (str, optional): Machine type
            data_disk_type (str, optional): Data disk type
            data_disk_size (int, optional): Data disk size
            data_disk_count (int, optional): Data disk count
        '''
        core_count = 0
        if machine_type and instances:
            machine_type_cores = 1
            try:
                if machine_type.startswith('custom-'):
                    machine_type_cores = int(machine_type.split('-')[-2])
                else:
                    machine_type_cores = int(machine_type.split('-')[-1])
            except ValueError: pass
            core_count = instances * machine_type_cores

        ssd_count = 0
        local_ssd_count = 0
        if all([data_disk_type, data_disk_count, data_disk_size]):
            if data_disk_type == 'local-ssd':
                local_ssd_count = data_disk_count * data_disk_size
            else:
                ssd_count = data_disk_count * data_disk_size

        conn = self.connection()
        project_quotas = conn.projects().get(project=self.project_id).execute()['quotas']
        for q in project_quotas:
            usage = int(q.get('usage') or 0)
            limit = int(q.get('limit') or 0)
            metric = q.get('metric')
            if not metric:
                log.error(q)
                continue
            metric = metric.lower().capitalize().replace('_', ' ')
            if limit and float(usage) / limit > percentage:
                log.warn("QUOTA ALERT: Using {} of {} {} for the project".format(usage, limit, metric))
            else:
                log.debug("Using {} of {} {} for the project".format(usage, limit, metric))

        region = self._zone_to_region(self.zones[0])
        region_quotas = conn.regions().get(project=self.project_id, region=region).execute()['quotas']
        for q in region_quotas:
            usage = int(q.get('usage') or 0)
            limit = int(q.get('limit') or 0)
            metric = q.get('metric')
            if not metric:
                continue

            if metric == 'CPUS':
                usage += core_count
            if metric == 'SSD_TOTAL_GB':
                usage += ssd_count
            if metric == 'LOCAL_SSD_TOTAL_GB':
                usage += local_ssd_count

            metric = metric.lower().capitalize().replace('_', ' ')
            if limit and float(usage) / limit > percentage:
                log.warn("QUOTA ALERT: Using {} of {} {} for the region".format(usage, limit, metric))
            else:
                log.debug("Using {} of {} {} for the region".format(usage, limit, metric))

    def _auth_http(self, scopes=None):
        '''Simple wrapper for the HTTP object credential authorization

            Do not call this directly, use connection() instead.

            Arguments:
                scopes ([str], optional): list of scopes to request, defaults to DEFAULT_SCOPES
        '''
        creds = None
        scopes = scopes or self.DEFAULT_SCOPES
        if self.access_token:
            from oauth2client.client import AccessTokenCredentials
            # we check for access_token presence but use the threading.local copy
            creds = AccessTokenCredentials(self.local.access_token, 'vFXT UserAgent/0.1')
        elif self.use_environment_for_auth:
            creds = oauth2client.client.GoogleCredentials.get_application_default()
        else:
            try:
                from oauth2client.service_account import ServiceAccountCredentials
                if self.key_data:
                    creds = ServiceAccountCredentials.from_json_keyfile_dict(self.key_data, scopes)
                elif self.key_file.endswith('.p12'):
                    creds = ServiceAccountCredentials.from_p12_keyfile(self.client_email, self.key_file, scopes)
                else:
                    raise vFXTConfigurationException("Unknown key file type: {}".format(self.key_file))
            except Exception as e:
                log.debug('Failed importing oauth2client.service_account (oauth2client 2.x), falling back to oauth2client 1.x: {}'.format(e))
                with open(self.key_file, 'rb') as f:
                    key = f.read()
                if self.key_file.endswith('.json'):
                    key = json.loads(key)['private_key']
                from oauth2client.client import SignedJwtAssertionCredentials
                creds = SignedJwtAssertionCredentials(self.client_email, key, scopes)

        proxy = None
        if self.proxy_uri:
            proxy = httplib2.proxy_info_from_url(self.proxy_uri)
        else:
            try:
                proxy = httplib2.proxy_info_from_environment()
            except Exception as e:
                log.debug("httplib2.proxy_info_from_environment(): {}".format(e))
        # maybe set this for those proxies that don't support CONNECT?
        # proxy.proxy_type = httplib2.socks.PROXY_TYPE_HTTP_NO_TUNNEL

        http = httplib2.Http(proxy_info=proxy,
                disable_ssl_certificate_validation=self.DISABLE_SSL_CERTIFICATE_VALIDATION, timeout=CONNECTION_TIMEOUT)
        return creds.authorize(http)

    def connection(self, connection_type='compute', version='v1', retries=CONNECTION_TIMEOUT, scopes=None):
        '''Connection factory, returns a new connection or thread local copy

            Arguments:
                connection_type (str, optional): connection type (compute, storage)
                version (str, optional): currently unused
                retries (int, optional): number of retries, default to vFXT.service.CONNECTION_TIMEOUT
                scopes ([str], optional): list of scopes to request, defaults to DEFAULT_SCOPES
        '''
        try:
            if self.local.instance_data['token_expires'] < int(time.time()):
                log.debug("Access token expired, forcing refresh")
                self.local.connections = {}
        except Exception:
            pass

        if not hasattr(self.local, 'connections'):
            self.local.connections = {}

        connection_sig = '{}_{}'.format(connection_type, version)
        if not self.local.connections.get(connection_sig, False):
            if self.access_token:
                self.local.instance_data = self.get_instance_data(source_address=self.source_address)
                self.local.access_token = self.local.instance_data['access_token']

            log.debug("Creating new {} connection object".format(connection_type))
            connection_attempts = 0
            while True:
                try:
                    self.local.connections[connection_sig] = googleapiclient.discovery.build(connection_type, version, http=self._auth_http(scopes=scopes))
                    break
                except Exception as e:
                    if connection_attempts == retries:
                        raise vFXTServiceConnectionFailure("Failed to establish connection to service: {}".format(e))
                    log.debug("Retrying failed connection attempt: {}".format(e))
                    connection_attempts += 1
                    time.sleep(backoff(connection_attempts))

        return self.local.connections[connection_sig]

    def find_instances(self, search=None, all_regions=True):
        '''Returns all or filtered list of instances

            Arguments:
                search (str, optional): search query
                all_regions (bool, optional): search all regions, not just the current

            Search examples:
                field [ne|eq] expression
                'name eq instance-name'
                'name eq (name1|name2|name3)'
                'name eq prefix.*$'
        '''
        conn = self.connection()
        instances = []
        for zone in self._zone_names(all_regions):
            page_token = None
            while True:
                try: # sometimes we can see a region/zone before we can inspect it
                    r =  _gce_do(conn.instances().list, project=self.project_id, filter=search, zone=zone, pageToken=page_token)
                    if r and 'items' in r:
                        instances.extend(r['items'])
                    if r and 'nextPageToken'  in r:
                        page_token = r['nextPageToken']
                    if not r or 'nextPageToken' not in r:
                        break
                except Exception:
                    break
        return instances

    def get_instances(self, instance_ids, all_regions=True):
        '''Returns a list of instances with the given instance ID list

            Arguments:
                instance_ids ([str]): list of instance id strings
                all_regions (bool, optional): search all regions, not just the current

            Returns:
                [objs]: list of backend instance objects
        '''
        id_str = '|'.join(instance_ids)
        search = 'name eq {}'.format(id_str)
        conn   = self.connection()
        instances = []
        for zone in self._zone_names(all_regions):
            try: # sometimes we can see a region/zone before we can inspect it
                r = _gce_do(conn.instances().list, project=self.project_id, filter=search, zone=zone)
                if r and 'items' in r:
                    instances.extend(r['items'])
            except Exception:
                pass
        return instances

    def get_instance(self, instance_id, all_regions=True):
        '''Get a specific instance by instance ID

            Arguments:
                instance_id (str)
                all_regions (bool, optional): search all regions, not just the current

            Returns:
                obj or None
        '''
        conn   = self.connection()
        for zone in self._zone_names(all_regions):
            try: # sometimes we can see a region/zone before we can inspect it
                return _gce_do(conn.instances().get, project=self.project_id, instance=instance_id, zone=zone)
            except Exception:
                pass
        return None

    def wait_for_status(self, instance, status, retries=ServiceBase.WAIT_FOR_STATUS):
        '''Poll on a given instance for status

            Arguments:
                instance (obj): backend instance object
                status (str): status string to watch for
                retries (int, optional): number of retries

            Raises: vFXTServiceTimeout
        '''
        s = '...' # in case our instance is not yet alive
        errors = 0
        while status != s:
            if retries % 10 == 0: # rate limit
                log.debug("Waiting for status: {} != {}".format(s, status))
            time.sleep(self.POLLTIME)
            try:
                instance = self.refresh(instance)
                s = self.status(instance)
            except Exception as e:
                log.debug('Ignored: {}'.format(e))
                errors += 1
                time.sleep(backoff(errors))
            retries -= 1
            if retries == 0:
                raise vFXTServiceTimeout("Timed out waiting for {} on {}".format(status, instance['name']))

    def _wait_for_operation(self, response, msg='operation to complete', retries=ServiceBase.WAIT_FOR_OPERATION, op_type='zoneOperations', zone=None):
        '''Wait for an operation to complete by polling the response

            Arguments:
                response (obj): response object from a prior service query
                msg (str, optional): string to debug log for this operation
                retries (int, optional): number of retries
                op_type (str, optional): zoneOperations, globalOperations, ...

            Raises: vFXTServiceFailure
        '''
        conn        = self.connection()
        op          = conn.__getattribute__(op_type)
        errors      = 0
        while response['status'] != 'DONE':
            try:
                time.sleep(self.POLLTIME)
                if retries % 10 == 0:
                    log.debug("Waiting for {}: {}".format(msg, response['status']))
                operation   = response['name']
                args        = {'project': self.project_id, 'operation': operation}
                if op_type == 'zoneOperations':
                    args['zone'] = zone or self.zones[0]
                response    = _gce_do(op().get, **args)
            except googleapiclient.errors.HttpError as e:
                if int(e.resp['status']) < 500:
                    if 'httpErrorMessage' in response:
                        raise vFXTServiceFailure("{}: {}".format(response['httpErrorMessage'], response['error']['errors'][0]['message']))
                    else:
                        raise vFXTServiceFailure(e)
                errors += 1
                time.sleep(backoff(errors))
            retries -= 1
            if retries == 0:
                raise vFXTServiceTimeout("Failed waiting for {}".format(msg))

        if 'httpErrorMessage' in response:
            log.debug("response {}".format(response))
            raise vFXTServiceFailure("{}: {}".format(response['httpErrorMessage'], response['error']['errors'][0]['message']))

    def can_stop(self, instance):
        ''' Some instance configurations cannot be stopped. Check if this is one.

            Arguments:
                instance: backend instance
        '''
        if 'SCRATCH' in [d['type'] for d in instance['disks']]:
            raise vFXTConfigurationException("Cannot stop instance {} with local-ssd disks".format(self.name(instance)))
        return True

    def stop(self, instance, wait=ServiceBase.WAIT_FOR_STOP):
        '''Stop an instance

            Arguments:
                instance: backend instance
        '''
        if not self.can_stop(instance):
            raise vFXTConfigurationException("Node configuration prevents them from being stopped")
        log.info("Stopping instance {}".format(self.name(instance)))
        conn        = self.connection()
        zone        = instance['zone'].split('/')[-1]
        response    = _gce_do(conn.instances().stop, project=self.project_id, zone=zone, instance=instance['name'])
        log.debug(response)
        self.wait_for_status(instance, self.OFF_STATUS, retries=wait)

    def start(self, instance, wait=ServiceBase.WAIT_FOR_START):
        '''Start an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
        '''
        log.info("Starting instance {}".format(self.name(instance)))
        conn        = self.connection()
        zone        = instance['zone'].split('/')[-1]
        response    =  _gce_do(conn.instances().start, project=self.project_id, zone=zone, instance=instance['name'])
        log.debug(response)
        self.wait_for_status(instance, self.ON_STATUS, retries=wait)

    def restart(self, instance, wait=ServiceBase.WAIT_FOR_RESTART):
        '''Restart an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
        '''
        if not self.can_stop(instance):
            raise vFXTConfigurationException("Node configuration prevents them from being restarted")
        log.info("Restarting instance {}".format(self.name(instance)))
        # GCE does not have a reboot option, only reset (which is not what we want)
        self.stop(instance)
        self.start(instance)

    def destroy(self, instance, wait=ServiceBase.WAIT_FOR_DESTROY, keep_root_disk=False):
        '''Destroy an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
                keep_root_disk (bool, optional): keep the root disk
        '''
        conn        = self.connection()
        zone        = instance['zone'].split('/')[-1]

        root_disk = None
        if keep_root_disk:
            root_disks = [ d for d in instance['disks'] if 'boot' in d and d['boot']]
            if not root_disks:
                raise vFXTServiceFailure("Failed to find root disk")
            root_disk = root_disks[0]
            self._disable_disk_auto_delete(instance, root_disk['deviceName'])

        log.info("Destroying instance {}".format(self.name(instance)))
        response =  _gce_do(conn.instances().delete, project=self.project_id, zone=zone, instance=instance['name'])
        # we wait because we cannot destroy resources still attached to the instance
        self._wait_for_operation(response, msg='instance {} to be destroyed'.format(instance['name']), retries=wait, zone=zone)

        for d in instance['disks']:
            # skip our root if we want to keep it
            if root_disk and d['deviceName'] == root_disk['deviceName']:
                continue
            try: # need to delete any leftover disks
                resp = _gce_do(conn.disks().delete, project=self.project_id, zone=zone, disk=d['deviceName'])
                self._wait_for_operation(resp, msg='disk to be deleted', zone=zone)
            except Exception:
                pass

        expr   = "nextHopInstance eq .*/{}$".format(instance['name'])
        routes = _gce_do(conn.routes().list, project=self.network_project_id, filter=expr)
        if not routes or 'items' not in routes:
            return
        for route in routes['items']:
            try: # need to delete any leftover routes
                resp = _gce_do(conn.routes().delete, project=self.network_project_id, route=route['name'])
                self._wait_for_operation(resp, msg='route to be deleted', zone=zone)
            except Exception:
                pass

    def is_on(self, instance):
        '''Return True if the instance is currently on

            Arguments:
                instance: backend instance
        '''
        return instance['status'] != self.OFF_STATUS

    def is_off(self, instance):
        '''Return True if the instance is currently off

            Arguments:
                instance: backend instance
        '''
        return instance['status'] == self.OFF_STATUS

    def is_shelved(self, instance):
        '''Return True if the instance is currently shelved

            Arguments:
                instance: backend instance
        '''
        try:
            metadata = instance['metadata']['items']
            return 'shelved' in [v for opts in metadata for v in opts.values()]
        except Exception:
            return False

    def name(self, instance):
        '''Returns the instance name (may be different from instance id)

            Arguments:
                instance: backend instance
        '''
        return instance['name']

    def instance_id(self, instance):
        '''Returns the instance id (may be different from instance name)

            Arguments:
                instance: backend instance
        '''
        return instance['name']

    def status(self, instance):
        '''Return the instance status

            Arguments:
                instance: backend instance
        '''
        return instance['status']

    def refresh(self, instance):
        '''Refresh the instance from the Google backend

            Arguments:
                instance: backend instance
        '''
        i = self.get_instance(instance['name'])
        if not i:
            raise vFXTConfigurationException("Failed to find instance: {}".format(instance['name']))
        return i

    def ip(self, instance):
        '''Return the primary IP address of the instance

            Arguments:
                instance: backend instance
        '''
        try:
            return instance['networkInterfaces'][0]['networkIP']
        except Exception:
            log.error("Unable to find first networkInterface networkIP in {}".format(instance))

    def fqdn(self, instance): # XXX revisit
        '''Provide the fully qualified domain name of the instance

            Arguments:
                instance: backend instance
        '''
        name = instance['name']
        return "{}.c.{}.internal".format(name, self.project_id)

    def can_shelve(self, instance):
        ''' Some instance configurations cannot be shelved. Check if this is one.

            Arguments:
                instance: backend instance
        '''
        if 'SCRATCH' in [d['type'] for d in instance['disks']]:
            log.error("Cannot shelve {} with local-ssd disks".format(instance['name']))
            return False
        return True

    def shelve(self, instance):
        ''' shelve the instance; shut it down, detach and delete
            all non-root block devices

            Arguments:
                instance: backend instance
            Raises: vFXTServiceFailure
        '''
        conn     = self.connection()
        zone     = instance['zone'].split('/')[-1]

        if not self.can_shelve(instance):
            raise vFXTConfigurationException("{} configuration prevents shelving".format(self.name(instance)))
        if self.is_shelved(instance):
            raise vFXTConfigurationException("{} is already shelved".format(self.name(instance)))

        if self.is_on(instance):
            self.stop(instance)
            instance = self.refresh(instance)

        disks          = instance['disks']
        non_root_disks = [ d for d in disks if 'boot' not in d or not d['boot'] ]

        if not non_root_disks:
            log.info("No non-root volumes for instance {}, already shelved?".format(instance['name']))
            return

        log.debug("Found non-root volumes: {}".format(non_root_disks))

        disk_srv      = conn.disks()
        errors        = ShelveErrors()
        detach_failed = []
        disk_size     = None
        disk_type     = None
        for nrd in non_root_disks:
            name = nrd['source'].split('/')[-1]
            data = _gce_do(disk_srv.get, project=self.project_id, zone=zone, disk=name)

            log.info("{}: detaching and deleting {}".format(instance['name'], name))

            try:
                r = _gce_do(conn.instances().detachDisk, project=self.project_id, zone=zone, instance=instance['name'], deviceName=nrd['deviceName'])
                self._wait_for_operation(r, msg='disk to be detached', zone=zone)
                r = _gce_do(disk_srv.delete, project=self.project_id, zone=zone, disk=name)
                self._wait_for_operation(r, msg='disk to be deleted', zone=zone)
            except Exception:
                detach_failed.append(name)

            # XXX assume all volume attributes are uniform
            disk_size = data['sizeGb']
            disk_type = data['type']

        if detach_failed:
            errors['notdetached'] = ','.join(detach_failed)

        shelved = "{}|{}|{}".format(len(non_root_disks), disk_size, disk_type)

        if errors:
            shelved += '|{}'.format(errors)

        log.debug("Creating shelved metadata: {}".format(shelved))
        instance = self.refresh(instance)
        self._set_metadata(instance, "shelved", shelved)

    def unshelve(self, instance, count_override=None, size_override=None, type_override=None, **options): #pylint: disable=unused-argument
        ''' bring our instance back to life.  This requires a metadata tag called
            shelved that contains the number of disks and their size/type

            Arguments:
                instance: backend instance
                count_override (int, optional): number of data disks
                size_override (int, optional): size of data disks
                type_override (str, optional): type of data disks

            Raises: vFXTServiceFailure
        '''
        conn     = self.connection()
        zone     = instance['zone'].split('/')[-1]

        # assume we've previously killed the data disks and set a tag
        if not self._get_metadata(instance, "shelved"):
            log.info( "{} does not have shelved tag, skipping".format(instance['name']))
            return

        # XXX assume instance is already stopped
        if self.is_on(instance):
            log.info("{} is not stopped, skipping".format(instance['name']))
            return

        try:
            attrs = self._get_metadata(instance, "shelved").split('|')
            vol_count, vol_size, vol_type = attrs[0:3]
        except Exception:
            log.error("{} does not have data in the shelved tag".format(instance['name']))
            return

        if len(instance['disks']) > 1:
            log.info("{} appears to already have data disks, skipping".format(instance['name']))
            return

        if count_override:
            vol_count = count_override
        if size_override:
            vol_size = size_override
        if type_override:
            vol_type = type_override

        i_srv           = conn.instances()
        d_srv           = conn.disks()
        disks_created   = []
        try:
            for i in range(int(vol_count)):
                disk_name   = "{}-data-{}".format(instance['name'], i + 1)
                body        = {'name': disk_name, "sizeGb": long(vol_size), 'type': vol_type}

                log.info("{}: creating {} volume {}".format(instance['name'], vol_size, disk_name))
                r = _gce_do(d_srv.insert, project=self.project_id, zone=zone, body=body)
                self._wait_for_operation(r, msg='disk to be created', zone=zone)

                d = _gce_do(d_srv.get, project=self.project_id, zone=zone, disk=disk_name)
                disks_created.append(d)

                body        = {'deviceName': disk_name, "source": d['selfLink'], "autoDelete": True}
                log.info("{}: attaching disk {}".format(instance['name'], disk_name))
                r = _gce_do(i_srv.attachDisk, project=self.project_id, zone=zone, instance=instance['name'], body=body)
                self._wait_for_operation(r, msg='disk to be attached', zone=zone)
        except Exception as e:
            log.debug(e)
            log.error("Error while creating volumes, undoing what we did")
            instance = self.refresh(instance)
            for d in disks_created:
                if d['name'] in [dev['deviceName'] for dev in instance['disks']]:
                    r = _gce_do(i_srv.detachDisk, project=self.project_id, zone=zone, instance=instance['name'], deviceName=d['name'])
                    self._wait_for_operation(r, msg='disk to be detached', zone=zone)
                r = _gce_do(d_srv.delete, project=self.project_id, zone=zone, disk=d['name'])
                self._wait_for_operation(r, msg='disk to be deleted', zone=zone)
            raise vFXTServiceFailure(e)

        self.start(instance)
        instance = self.refresh(instance)
        self._delete_metadata(instance, 'shelved')

    # No GCE equivalent
    def wait_for_service_checks(self, instance, retries=ServiceBase.WAIT_FOR_SERVICE_CHECKS): pass

    # storage/buckets
    def create_bucket(self, name, **options):
        '''Create a bucket

            Arguments:
                name (str): bucket name to create
                storage_class (str, optional): storage class of MULTI_REGIONAL, REGIONAL,
                    STANDARD, NEARLINE, COLDLINE, and DURABLE_REDUCED_AVAILABILITY
                region (str, optional): region for the bucket if using REGIONAL (defaults to service default region)
                tags (dict, optional): tag labels to apply to the bucket

            Raises: vFXTServiceFailure
        '''
        if not self.valid_bucketname(name):
            raise vFXTConfigurationException("{} is not a valid bucket name".format(name))
        storage_service = self.connection(connection_type='storage')

        storage_class = options.get('storage_class') or 'STANDARD'
        if not storage_class in self.STORAGE_CLASSES:
            raise vFXTConfigurationException("{} is not a valid storage class".format(storage_class))

        body = {'name': name, 'storageClass': storage_class}
        if storage_class == 'REGIONAL':
            region = options.get('region') or self._zone_to_region(self.zones[0])
            body['location'] = region
        if 'tags' in options:
            labels = options.get('tags')
            bad_name_re = re.compile('[^a-z_]')
            filtered_labels = {k: v for k, v in labels.iteritems() if not k.startswith('_') and not re.search(bad_name_re, k)}
            if len(filtered_labels) != len(labels):
                l_keys = set(labels.keys())
                fl_keys = set(filtered_labels.keys())
                err = "Discarding invalid bucket labels: {}".format(', '.join(l_keys - fl_keys))
                log.error(err)
            body['labels'] = filtered_labels
        log.debug("Bucket create request {}".format(body))
        return _gce_do(storage_service.buckets().insert, project=self.project_id, body=body)

    def delete_bucket(self, name):
        '''Delete a bucket

            Arguments:
                name (str): bucket name

            Raises: vFXTServiceFailure
        '''
        try:
            storage_service = self.connection(connection_type='storage')
            _gce_do(storage_service.buckets().delete, bucket=name)
        except Exception as e:
            raise vFXTServiceFailure("Failed to delete bucket {}: {}".format(name, e))

    def authorize_bucket(self, cluster, name, retries=ServiceBase.CLOUD_API_RETRIES, xmlrpc=None):
        '''Perform any backend work for the bucket, and register a credential
        for it to the cluster

            No authorization is currently performed for GCE.

            Arguments:
                cluster (Cluster): cluster object
                name (str): bucket name
                retries (int, optional): number of attempts to make
                xmlrpc (xmlrpcClt, optional): number of attempts to make

            Raises: vFXTServiceFailure
        '''
        xmlrpc = cluster.xmlrpc() if xmlrpc is None else xmlrpc

        existing_creds = cluster._xmlrpc_do(xmlrpc.corefiler.listCredentials, _xmlrpc_do_retries=retries)

        # see if we have s3 interop credentials
        if self.s3_access_key and self.s3_secret_access_key:
            log.debug("Found s3 access keys")
            cred_name = 's3-{}'.format(cluster.name)

            # if it exists, use it
            if cred_name in [c['name'] for c in existing_creds]:
                return cred_name

            log.debug("Creating credential {}".format(cred_name))
            cred_body = {
                'accessKey': self.s3_access_key,
                'privateKey': self.s3_secret_access_key,
            }
            r = cluster._xmlrpc_do(xmlrpc.corefiler.createCredential, cred_name, self.COREFILER_CRED_TYPE, cred_body)
            if r != 'success':
                raise vFXTConfigurationException("Could not create credential {}: {}".format(cred_name, r))
            return cred_name

        # otherwise use the first default
        if not existing_creds:
            raise vFXTConfigurationException("Could not find existing credential to use")
        return existing_creds[0]['name']

    # networking
    def get_default_router(self, subnetwork=None):
        '''Get default route address

            Arguments:
                subnetwork (str, optional): subnetwork name

            Returns:
                str: address of default router
        '''
        network = self._get_network()

        if 'gatewayIPv4' in network:
            return network['gatewayIPv4']

        if 'subnetworks' in network:
            region = self._zone_to_region(self.zones[0])
            region_gateways = [] # subnetwork gateways associated with our region
            subnetwork = subnetwork or self.subnetwork_id

            # try to find a direct match if we have a subnetwork
            subnetworks = self._get_subnetworks(region)
            for sn in subnetworks:
                if subnetwork and sn['name'] == subnetwork:
                    return sn['gatewayAddress']
                region_gateways.append(sn['gatewayAddress'])

            # otherwise pick one associated with our region
            if region_gateways:
                return region_gateways[0]

        raise vFXTConfigurationException("Unable to determine default router for this configuration")

    def get_dns_servers(self):
        '''Get DNS server addresses

            Returns:
                [str]: list of DNS server addresses
        '''
        dns = []
        dns.extend(self.DNS_SERVERS)
        dns.insert(0, self.get_default_router())
        return dns

    def get_ntp_servers(self):
        '''Get NTP server addresses

            Returns:
                [str]: list of NTP server addresses
        '''
        return self.NTP_SERVERS

    def in_use_addresses(self, cidr_block, category='all'):
        '''Return a list of in use addresses within the specified cidr

            Arguments:
                cidr_block (str)
                category (str): all, interfaces, routes
        '''
        conn      = self.connection()
        c         = Cidr(cidr_block)
        addresses = set()

        if category in ['all', 'interfaces']:
            for instance in self.find_instances(all_regions=True):
                for interface in instance['networkInterfaces']:
                    interface_address = interface.get('networkIP')
                    if interface_address:
                        if c.contains(interface_address):
                            addresses.add(interface_address)
                    if 'aliasIpRanges' in interface:
                        ip_aliases = interface.get('aliasIpRanges')
                        for ip_alias in ip_aliases:
                            if '/' in ip_alias['ipCidrRange'] and ip_alias['ipCidrRange'].split('/')[-1] != '32':
                                alias_range = Cidr(ip_alias['ipCidrRange'])
                                alias_addresses = Cidr.expand_address_range(alias_range.start_address(), alias_range.end_address())
                                addresses.update(alias_addresses)
                                continue
                            alias_address = ip_alias['ipCidrRange'].split('/')[0]
                            if c.contains(alias_address):
                                addresses.add(alias_address)

        if category in ['all', 'routes']:
            search = 'destRange eq .*/32' # only point to point addresses
            resp   = _gce_do(conn.routes().list, project=self.network_project_id, filter=search)
            if resp and 'items' in resp:
                for route in resp['items']:
                    # skip if we don't have a next hop instance (dangling route)
                    if any([_['code'] == 'NEXT_HOP_INSTANCE_NOT_FOUND' for _ in route.get('warnings', [])]) or 'nextHopInstance' not in route:
                        continue
                    addr = route['destRange'].split('/')[0]
                    if c.contains(addr):
                        addresses.add(addr)

        return list(addresses)

    def _cidr_overlaps_network(self, cidr_range):
        '''Check if a given cidr range falls within any of the network/subnetwork ranges
            of the current configuration

            cidr_range (str): IP address range in CIDR notation
        '''
        cidr = Cidr(cidr_range)
        address = cidr.start_address()
        network = self._get_network()
        if 'subnetworks' in network:
            subnetwork = self._get_subnetwork(self.subnetwork_id)
            for r in subnetwork.get('secondaryIpRanges', []):
                if 'ipCidrRange' not in r:
                    continue
                secondary_range = Cidr(r['ipCidrRange'])
                if secondary_range.contains(address):
                    return True
            if 'ipCidrRange' in subnetwork:
                subnetwork_range = Cidr(subnetwork['ipCidrRange'])
                if subnetwork_range.contains(address):
                    return True
        else: # legacy
            network_range = Cidr(network['IPv4Range'])
            if network_range.contains(address):
                return True
        return False

    def get_available_addresses(self, count=1, contiguous=False, addr_range=None, in_use=None):
        '''Returns a list of available addresses for the given range
            Arguments:
                count (int, optional): number of addresses required
                contiguous (bool=False): addresses must be contiguous
                addr_range (str, optional): address range cidr block
                in_use ([str], optional): list of addresses known to be used

            Returns:
                ([], str): tuple of address list and netmask str

            Raises: vFXTConfigurationException
        '''
        honor_reserves = True # leave out reserved (first 4) addresses in a cidr range

        # find an unused range, either provided or default
        addr_range = addr_range or self.private_range
        if addr_range:
            log.debug("Using specified address range {}".format(addr_range))
        else:
            network = self._get_network()
            if 'subnetworks' in network:
                subnetwork = self._get_subnetwork(self.subnetwork_id)
                if 'secondaryIpRanges' in subnetwork:
                    honor_reserves = False
                    r = subnetwork['secondaryIpRanges'][0] # XXX only using the first one (support more than one if avail?)
                    addr_range = r['ipCidrRange']
                    log.debug("Using subnetwork {} {} secondary range of {}".format(subnetwork['name'], r.get('rangeName', 'unnamed'), r['ipCidrRange']))
                else:
                    log.debug("Using subnetwork {} range of {}".format(subnetwork['name'], subnetwork['ipCidrRange']))
                    addr_range = subnetwork['ipCidrRange']
        # otherwise we use our defaults
        addr_range = addr_range or self.DEFAULT_CLUSTER_NETWORK_RANGE

        used = self.in_use_addresses(addr_range)
        if in_use:
            used.extend(in_use)
            used = list(set(used))
        addr_cidr = Cidr(addr_range)

        try:
            avail   = addr_cidr.available(count, contiguous, used, honor_reserves)
            netmask = "255.255.255.255" # hardcoded for gce /32
            return (avail, netmask)
        except Exception as e:
            raise vFXTConfigurationException("Check that the subnetwork or specified address range has enough free addresses: {}".format(e))

    def export(self):
        '''Export the service object in an easy to serialize format
            Returns:
                {}: serializable dictionary
        '''
        data = {
            'zone': self.zones,
            'network_id': self.network_id,
            'client_email': self.client_email,
            'project_id': self.project_id
        }
        if self.key_file:
            data['key_file'] = self.key_file
        if self.key_data:
            data['key_data'] = self.key_data
        if self.access_token:
            data['access_token'] = self.access_token
        if self.s3_access_key:
            data['s3_access_key'] = self.s3_access_key
        if self.s3_secret_access_key:
            data['s3_secret_access_key'] = self.s3_secret_access_key
        if self.private_range:
            data['private_range'] = self.private_range
        if self.proxy_uri:
            data['proxy_uri'] = self.proxy_uri
        if self.subnetwork_id:
            data['subnetwork_id'] = self.subnetwork_id
        return data

    def create_instance(self, machine_type, name, boot_disk_image, other_disks=None, **options):
        '''Create and return a GCE instance

            Arguments:
                machine_type (str): GCE machine type
                name (str): name of the instance
                boot_disk_image (str): the name of the disk image for the root disk
                boot_disk (str, optional): the name of an existing disk for use as the root disk (instead of a disk image)
                other_disks ([], optional): GCE disk definitions
                metadata (dict, optional): metadata tags to apply to instance
                disk_type (str, optional): type of disk to use for root disk
                root_size (int, optional): root disk size in GB
                tags ([], optional): list of GCE network tags to apply to the instance
                labels ({}, optional): dictionary of GCE labels to apply to the instance
                zone (str, optional): create in custom zone
                auto_public_address (bool, optional): auto assign a public address (defaults to False)
                private_ip_address (str, optional): primary private IP address
                wait_for_success (int, optional): wait time for the instance to report success (default WAIT_FOR_SUCCESS)
                service_account (str, optional): Service account name to start the instance with (defaults to the default service account)
                scopes ([], optional): List of service scopes for the instance (default DEFAULT_SCOPES)
                subnetwork (str, optional): subnetwork path (projects/project-foo/regions/us-east1/subnetworks/foo)

            Raises: vFXTConfigurationException, vFXTServiceFailure

            Service failures here are uncaught exceptions and should be handled
            by the caller.

            boot_disk_image format is the image name for local images (or the more
            formal global/images/my-private-image).  For images from other projects,
            the format is projects/<project>/global/images/<image name>.  The full
            URL also is accepted.
        '''
        if not self.valid_instancename(name):
            raise vFXTConfigurationException("{} is not a valid instance name".format(name))
        if self.get_instance(name):
            raise vFXTConfigurationException("{} exists".format(name))

        machine_defs = self.MACHINE_DEFAULTS[machine_type]

        conn       = self.connection()
        network    = self._get_network()
        zone       = options.get('zone') or self.zones[0]
        subnetwork = options.get('subnetwork') or self.subnetwork_id
        disk_type  = options.get('disk_type') or machine_defs['root_disk_type']
        root_size  = options.get('root_size') or None
        metadata   = options.get('metadata', None)
        disk_type  = _gce_do(conn.diskTypes().get, project=self.project_id, zone=zone, diskType=disk_type)

        boot_image = {}

        if boot_disk_image:
            try:
                boot_image = _gce_do(conn.images().get, project=self.project_id, image=boot_disk_image)
            except Exception:
                log.debug("Could not find boot_disk_image in our list of images, assuming public/other")
                boot_image['selfLink'] = boot_disk_image

        # gce instance defaults
        # https://cloud.google.com/compute/docs/reference/latest/instances#resource
        body = {}
        body['name'] = name
        body['machineType'] = "{}/{}/zones/{}/machineTypes/{}".format(self.GCE_URL, self.project_id, zone, machine_type)
        body['disks'] = [{
                'autoDelete': True,
                'boot': True,
                'type': 'PERSISTENT',
                'deviceName': '{}-boot'.format(name),
            }
        ]
        if options.get('boot_disk'):
            # fetch the disk
            boot_disk = _gce_do(conn.disks().get, project=self.project_id, zone=zone, disk=options.get('boot_disk'))
            body['disks'][0]['autoDelete'] = False
            body['disks'][0]['source'] = boot_disk['selfLink']
        else:
            body['disks'][0]['initializeParams'] = {
                'diskName': '{}-boot'.format(name),
                'diskType': disk_type['selfLink'],
                'sourceImage': boot_image['selfLink']
            }
            if root_size:
                body['disks'][0]['initializeParams']['diskSizeGb'] = long(root_size)
        if other_disks:
            body['disks'].extend(other_disks)

        body['networkInterfaces'] = [{'network': network['selfLink']}]

        if subnetwork:
            subnetwork = self._get_subnetwork(subnetwork)
            body['networkInterfaces'][0]['subnetwork'] = subnetwork['selfLink']
            body['networkInterfaces'][0]['network'] = subnetwork['network']
        else:
            subnetwork_region = self._zone_to_region(zone)
            subnetworks = [_ for _ in self._get_subnetworks(subnetwork_region)]
            if subnetworks: # no subnetwork specified, but we have them so use one
                subnetwork = subnetworks[0]
                log.warning("No subnetwork specified, picking {}".format(subnetwork['selfLink']))
                body['networkInterfaces'][0]['subnetwork'] = subnetwork['selfLink']
                body['networkInterfaces'][0]['network'] = subnetwork['network']

        # optional ephemeral address
        if options.get('auto_public_address', False):
            nat_name = '{}-nat'.format(name)
            nat_config = [{'kind': 'compute#accessConfig', 'type': 'ONE_TO_ONE_NAT', 'name': nat_name}]
            body['networkInterfaces'][0]['accessConfigs'] = nat_config
        if options.get('private_ip_address', False):
            body['networkInterfaces'][0]['networkIP'] = options.get('private_ip_address')
        if 'secondary_addresses' in options:
            body['networkInterfaces'][0]['aliasIpRanges'] = []
            for secondary_address in options.get('secondary_addresses'):
                ip_cidr_range = {'ipCidrRange': secondary_address}
                # if this is part of a subnetwork secondary range, we have to name it
                if subnetwork:
                    for secondary_range in subnetwork.get('secondaryIpRanges', []):
                        if Cidr(secondary_range['ipCidrRange']).contains(secondary_address):
                            ip_cidr_range['subnetworkRangeName'] = secondary_range['rangeName']
                body['networkInterfaces'][0]['aliasIpRanges'].append(ip_cidr_range)

        scopes = options.get('scopes') or self.DEFAULT_SCOPES
        if not isinstance(scopes, list) or not all([_.startswith('http') for _ in scopes]):
            raise vFXTConfigurationException("Invalid scopes: {}".format(scopes))
        body['serviceAccounts'] = [{
            'email': options.get('service_account') or 'default',
            'scopes' : scopes
        }]
        body['canIpForward'] = True
        body['tags'] = {'items': []}
        body['labels'] = {}
        body['metadata'] = {'items': []}

        if 'tags' in options:
            body['tags']['items'].extend(options['tags'])
        if 'labels' in options:
            body['labels'] = options['labels'].copy()

        if metadata:
            # google wants a list of this dict :-/
            pairs = [{'key': k, 'value': v} for k, v in metadata.iteritems()]
            body['metadata']['items'].extend(pairs)

        log.debug("create_instance request body: {}".format(body))

        try:
            request_id = str(uuid.uuid4())
            r = _gce_do(conn.instances().insert, project=self.project_id, zone=zone, requestId=request_id, body=body)
            wait_for_success = options.get('wait_for_success') or self.WAIT_FOR_SUCCESS
            self._wait_for_operation(r, msg='instance {} to be created'.format(name), retries=wait_for_success, zone=zone)
            retries = self.CLOUD_API_RETRIES
            while retries > 0:
                n = self.get_instance(name)
                if n:
                    return n
                retries -= 1
                time.sleep(self.POLLTIME)
            raise vFXTServiceFailure("Unable to locate the created instance {}".format(name))
        except Exception as e:
            raise vFXTServiceFailure("Create instance failed: {}".format(e))

    def create_node(self, node_name, cfg, node_opts, instance_options):
        '''Create a cluster node

            This is a frontend for create_instance that handles vFXT node specifics

            Arguments:
                node_name (str): name of the node
                cfg (str): configuration string to pass to the node
                node_opts (dict): node creation options
                instance_options (dict): options passed to create_instance

                node_opts include:
                    data_disk_size: size of data disks (in MB)
                    data_disk_type: disk type of data disk (pd-standard, pd-ssd, local-ssd)
                    data_disk_count: number of data disks
                    data_disk_nvme (bool): use NVME instead of SCSI
                    metadata (dict)
                    machine_type
                    root_image: disk image name
                    disk_type: root disk type

        '''
        conn = self.connection()
        if self.get_instance(node_name):
            raise vFXTNodeExistsException("Node {} exists".format(node_name))

        use_local_ssd = False
        if node_opts['data_disk_type'] == 'local-ssd':
            use_local_ssd = True
            # local-ssd sizes cannot be anything but 375
            node_opts['data_disk_size'] = 375
            if int(node_opts['data_disk_count']) > 8:
                raise vFXTConfigurationException("{} is larger than 8, the maximum for number of local-ssd disks".format(node_opts['data_disk_count']))

        zone = instance_options.get('zone') or self.zones[0]
        data_disk_url = _gce_do(conn.diskTypes().get, project=self.project_id, zone=zone, diskType=node_opts['data_disk_type'])['selfLink']
        data_disk_disks = []
        try:
            node_meta = node_opts.get('metadata', {})
            node_meta['cluster_cfg'] = cfg

            for idx in range(node_opts['data_disk_count']):
                data_disk_name = "{}-data-{}".format(node_name, idx + 1)
                data_disk_disk = {}
                # local-ssd can only be created atomically with the instance so
                # we only define it here
                if use_local_ssd:
                    data_disk_disk = {
                        'autoDelete': True,
                        'type': 'SCRATCH',
                        'interface': 'NVME' if node_opts.get('data_disk_nvme') else 'SCSI',
                        'deviceName': data_disk_name,
                        'initializeParams': {
                            'diskType': data_disk_url,
                            'diskSizeGb': node_opts['data_disk_size'],
                        },
                    }
                else: # otherwise, create the data disks before the instance
                    body = {'name': data_disk_name, 'sizeGb': long(node_opts['data_disk_size']), 'type': data_disk_url}
                    log.info("Creating data disk {} for {}".format(idx + 1, node_name))
                    log.debug("data disk request body: {}".format(body))
                    r    = _gce_do(conn.disks().insert, project=self.project_id, zone=zone, body=body)
                    self._wait_for_operation(r, msg='disk to be created', zone=zone)
                    created_disk = _gce_do(conn.disks().get, project=self.project_id, zone=zone, disk=data_disk_name)
                    data_disk_disk    = {'autoDelete': True, 'type': 'PERSISTENT', 'source': created_disk['selfLink'], 'deviceName': data_disk_name}

                data_disk_disks.append(data_disk_disk)

            log.info("Creating node {}".format(node_name))
            n = self.create_instance(machine_type=node_opts['machine_type'],
                            name=node_name,
                            boot_disk_image=node_opts['root_image'],
                            disk_type=node_opts.get('disk_type') or None,
                            other_disks=data_disk_disks,
                            metadata=node_meta,
                            **instance_options
            )
            log.info("Created {} ({})".format(n['selfLink'], n['networkInterfaces'][0]['networkIP']))
            return n

        except (vFXTServiceFailure, vFXTConfigurationException) as e:
            log.debug(e)
            n = self.get_instance(node_name)
            if n:
                self.destroy(n)
            elif data_disk_disks:
                for data_disk_disk in data_disk_disks:
                    if data_disk_disk['type'] != 'PERSISTENT': # only created disks
                        continue
                    try:
                        log.debug("Removing data disk {}".format(data_disk_disk['deviceName']))
                        r = _gce_do(conn.disks().delete, project=self.project_id, zone=zone, disk=data_disk_disk['deviceName'])
                        self._wait_for_operation(r, msg='disk to be deleted', zone=zone)
                    except Exception as disk_e:
                        log.error("Failed to remove data disk: {}".format(disk_e))
            raise

    def create_cluster(self, cluster, **options):
        '''Create a vFXT cluster (calls create_node for each node)
            Typically called via vFXT.Cluster.create()

            Arguments:
                cluster (vFXT.cluster.Cluster): cluster object
                size (int, optional): size of cluster (node count)
                root_image (str, optional): root disk image name
                disk_type (str, optional): root disk type
                data_disk_size (int, optional): size of data disk (or machine type default)
                data_disk_count (int, optional): number of data disks (or machine type default)
                data_disk_type (str, optional): type of data disks (or machine type default)
                metadata (dict, optional): metadata for instance
                config_expiration (int, optional): expiration time for cluster join configuration
                skip_cleanup (bool, optional): do not clean up on failure
                zones ([str], optional): one or more zones
                management_address (str, optional): management address for the cluster
                instance_addresses ([], optional): list of instance addresses to use (passed to create_cluster(private_ip_address))
                address_range_start (str, optional): The first of a custom range of addresses to use for the cluster
                address_range_end (str, optional): The last of a custom range of addresses to use for the cluster
                address_range_netmask (str, optional): cluster address range netmask

                Additional arguments are passed through to create_node()

            Raises: vFXTConfigurationException, vFXTCreateFailure

            root_image format is the image name for local images (or the more
            formal global/images/my-private-image).  For images from other projects,
            the format is projects/<project>/global/images/<image name>.  The full
            URL also is accepted.
        '''
        if not all([cluster.mgmt_ip, cluster.mgmt_netmask, cluster.cluster_ip_start, cluster.cluster_ip_end]):
            raise vFXTConfigurationException("Cluster networking configuration is incomplete")

        # if using shared vpc/xpn, we cannot use routes for addressing
        if self.project_id != self.network_project_id:
            if not self._cidr_overlaps_network('{}/32'.format(cluster.cluster_ip_start)):
                raise vFXTConfigurationException("Cluster addresses must reside within the Shared VPC address ranges")

        zones = options.get('zones') or self.zones
        zones = [zones] if isinstance(zones, basestring) else zones
        # extend our service zones if necessary
        for z in zones:
            if z not in self.zones:
                self.zones.append(z)
        cluster.zones = [zones[0]] # first node zone

        machine_type    = cluster.machine_type
        if machine_type not in self.MACHINE_TYPES:
            raise vFXTConfigurationException("{} is not a valid instance type".format(machine_type))
        zone_machine_types = self._zone_machine_types()
        if not all([_ for _ in zones if _ in zone_machine_types.keys() and machine_type in zone_machine_types[_]]):
            err = "{} is not available in all requested zones: {}".format(machine_type, ', '.join(zones))
            raise vFXTConfigurationException(err)

        machine_defs    = self.MACHINE_DEFAULTS[machine_type]
        cluster_size    = int(options.get('size', machine_defs['node_count']))

        log.info('Creating cluster configuration')
        cfg = cluster.cluster_config(expiration=options.get('config_expiration', None))
        log.debug("Generated cluster config: {}".format(cfg.replace(cluster.admin_password, '[redacted]')))
        # gce needs them base64 encoded
        cfg = ''.join(cfg.encode('base64').split()).strip()

        disk_type   = options.get('disk_type') or machine_defs['root_disk_type']
        root_image  = options.get('root_image') or self._get_default_image()

        data_disk_size  = options.get('data_disk_size') or machine_defs['data_disk_size']
        data_disk_count = options.get('data_disk_count') or machine_defs['data_disk_count']
        data_disk_type  = options.get('data_disk_type') or machine_defs['data_disk_type']
        data_disk_nvme  = options.get('data_disk_nvme', False)

        metadata    = options.pop('metadata', {})

        instance_addresses = cluster.instance_addresses or [None] * cluster_size
        # our private addresses must be inside the network ranges
        if instance_addresses[0] and not self._cidr_overlaps_network('{}/32'.format(instance_addresses[0])):
            log.debug("Resetting instance addresses to be provided via the backend service")
            instance_addresses = [None] * cluster_size

        try:
            # create the initial node
            name = '{}-{:02}'.format(cluster.name, 1)
            opts = {'data_disk_count': data_disk_count, 'data_disk_size': data_disk_size,
                    'data_disk_type': data_disk_type, 'metadata': metadata.copy(),
                    'machine_type': machine_type, 'root_image': root_image,
                    'disk_type': disk_type, 'data_disk_nvme': data_disk_nvme}
            options['zone'] = zones[0] # first node zone
            options['private_ip_address'] = instance_addresses.pop(0)
            n    = self.create_node(name, cfg, node_opts=opts, instance_options=options)
            cluster.nodes.append(ServiceInstance(service=self, instance=n))

            threads = []
            if not options.get('skip_configuration'):
                t = threading.Thread(target=cluster.first_node_configuration)
                t.setDaemon(True)
                t.start()
                threads.append(t)
            options.update(opts)
            options['instance_addresses'] = instance_addresses
            options['zone'] = zones if len(zones) == 1 else zones[1:]
            self.add_cluster_nodes(cluster, cluster_size - 1, **options)
            # do a timeout join to handle KeyboardInterrupts
            while all([_.is_alive() for _ in threads]):
                for t in threads:
                    t.join(10)
            if cluster.first_node_error:
                raise cluster.first_node_error
        except vFXTNodeExistsException as e:
            log.error("Failed to create node: {}".format(e))
            raise
        except (KeyboardInterrupt, Exception) as e:
            if not log.isEnabledFor(logging.DEBUG):
                log.exception(e)
            log.error("Failed to create nodes: {}".format(e))
            if not options.get('skip_cleanup', False):
                cluster.destroy(quick_destroy=True)
            raise vFXTCreateFailure(e)

    def post_destroy_cluster(self, cluster):
        '''Post cluster destroy cleanup'''
        pass

    def add_cluster_nodes(self, cluster, count, **options):
        '''Add nodes to the cluster (delegates to create_node())

            Arguments:
                cluster (vFXT.cluster.Cluster): cluster object
                count (int): number of nodes to add
                skip_cleanup (bool, optional): do not clean up on failure
                **options: passed to create_node()

            Raises: exceptions from create_node()
        '''
        if count < 1: return

        zones = options.get('zone') or cluster.zones if hasattr(cluster, 'zones') else self.zones
        zones = [zones] if isinstance(zones, basestring) else zones
        # make sure to use unused zones first, but account for our cluster zones
        zones.extend([z for z in cluster.zones if z not in zones])
        cycle_zones = cycle(zones)

        instance_addresses = options.pop('instance_addresses', [None] * count)
        if len(instance_addresses) != count:
            raise vFXTConfigurationException("Not enough instance addresses provided, require {}".format(count))
        if instance_addresses[0] and not self._cidr_overlaps_network('{}/32'.format(instance_addresses[0])):
            log.debug("Resetting instance addresses to be provided via the backend service")
            instance_addresses = [None] * count

        # look at cluster.nodes[0].instance
        instance       = cluster.nodes[0].instance
        instance_zone  = instance['zone'].split('/')[-1]
        disks          = instance['disks']
        root_disk      = [d for d in disks if 'boot' in d and d['boot']][0]
        non_root_disks = [d for d in disks if 'boot' not in d or not d['boot']]
        data_disk_count = options.get('data_disk_count', len(non_root_disks))
        if data_disk_count == 0:
            raise vFXTConfigurationException("Cannot determine data disk configuration")
        if 'items' in instance['tags'] and not options.get('tags'):
            options['tags'] = instance['tags']['items']
        if 'email' in instance['serviceAccounts'] and 'service_account' not in options:
            options['service_account'] = instance['serviceAccounts']['email']

        metadata = {opt['key']: opt['value'] for opt in instance['metadata']['items']}
        # overrides
        opts = {'data_disk_count': data_disk_count, 'metadata': metadata, 'machine_type': cluster.machine_type}
        overrides = ['machine_type', 'data_disk_size', 'data_disk_type', 'root_image', 'disk_type']
        for o in overrides:
            if o in options:
                opts[o] = options.pop(o)

        if 'metadata' in options: # even if empty
            opts['metadata'].update(options.pop('metadata') or {})

        conn = None

        # root disk info
        if 'root_image' not in opts or 'disk_type' not in opts:
            conn = self.connection()
            disk_name      = root_disk['source'].split('/')[-1]
            disk_data      = _gce_do(conn.disks().get, project=self.project_id, zone=instance_zone, disk=disk_name)
            disk_type      = disk_data['type'].split('/')[-1]
            root_image     = disk_data['sourceImage'] if 'sourceImage' in disk_data else self._get_default_image()
            if 'root_image' not in opts:
                opts['root_image'] = root_image
            if 'disk_type' not in opts:
                opts['disk_type'] = disk_type

        # data info
        if 'data_disk_size' not in opts or 'data_disk_type' not in opts:
            data_disk_size = None
            data_disk_type = None
            if not conn:
                conn = self.connection()
            if non_root_disks[0]['type'] == 'SCRATCH':
                data_disk_type = _gce_do(conn.diskTypes().get, project=self.project_id, zone=instance_zone, diskType='local-ssd')['selfLink'].split('/')[-1]
                # there is not API to query the size of a non-persistent disk
                data_disk_size = 375
            else:
                disk_name      = non_root_disks[0]['source'].split('/')[-1]
                disk_data      = _gce_do(conn.disks().get, project=self.project_id, zone=instance_zone, disk=disk_name)
                data_disk_size = disk_data['sizeGb']
                data_disk_type = disk_data['type'].split('/')[-1]
            if 'data_disk_size' not in opts:
                opts['data_disk_size'] = data_disk_size
            if 'data_disk_type' not in opts:
                opts['data_disk_type'] = data_disk_type

        # Requires cluster be online
        # XXX assume our node name always ends in the node number
        max_node_num = max([int(i.name().split('-')[-1]) for i in cluster.nodes])

        joincfg = cluster.cluster_config(joining=True, expiration=options.get('config_expiration', None))
        joincfg = ''.join(joincfg.encode('base64').split()).strip()

        nodeq   = Queue.Queue()
        failq   = Queue.Queue()
        threads = []
        def cb(nodenum, inst_opts, nodeq, failq):
            '''callback'''
            try:
                name = '{}-{:02}'.format(cluster.name, nodenum)
                n    = self.create_node(name, joincfg, node_opts=opts, instance_options=inst_opts)
                nodeq.put(n)
            except Exception as e:
                if not log.isEnabledFor(logging.DEBUG):
                    log.exception(e)
                failq.put(e)

        for node_num in xrange(max_node_num, max_node_num + count):
            next_node_num = node_num + 1
            inst_opts = options.copy()
            inst_opts['zone'] = next(cycle_zones)
            inst_opts['private_ip_address'] = instance_addresses.pop(0)
            t = threading.Thread(target=cb, args=(next_node_num, inst_opts, nodeq, failq,))
            t.setDaemon(True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        nodes = []
        while True:
            try:
                n = nodeq.get_nowait()
                nodes.append(ServiceInstance(service=self, instance=n))
            except Queue.Empty:
                break

        failed = []
        while True:
            try:
                failed.append(failq.get_nowait())
            except Queue.Empty:
                break
        if failed:
            if not options.get('skip_cleanup', False):
                for n in nodes:
                    n.destroy()
            raise Exception(failed)

        cluster.nodes.extend(nodes)

    def load_cluster_information(self, cluster, **options):
        '''Loads cluster information from the service and cluster itself
        '''
        xmlrpc = cluster.xmlrpc()

        # make sure mgmt_ip is set to the valid address (in case we used
        # a node address to get in)
        cluster.mgmt_ip = xmlrpc.cluster.get()['mgmtIP']['IP']

        node_ips = set([n['primaryClusterIP']['IP']
                        for name in xmlrpc.node.list()
                        for n in [xmlrpc.node.get(name)[name]]
                        if 'primaryClusterIP' in n])

        # lookup nodes that have one of our primary IP addresses..
        nodes = []
        for node_ip in node_ips:
            node = self._who_has_ip(node_ip)
            if node:
                nodes.append(node)
        if nodes:
            cluster.nodes        = [ServiceInstance(self, instance=n) for n in nodes]
            cluster.zones        = list(set([node['zone'].split('/')[-1] for node in nodes]))
            # XXX assume all instances have the same settings
            n                    = nodes[0]
            cluster.machine_type = n['machineType'].split('/')[-1]
            cluster.project_id   = n['zone'].split('/')[-3]
            cluster.network_project_id = self._get_network_project()
            cluster.network_id   = n['networkInterfaces'][0]['network'].split('/')[-1]
            cluster.name         = self.CLUSTER_NODE_NAME_RE.search(cluster.nodes[0].name()).groups()[0]

    # gce specific
    def _get_network(self):
        '''Get the network object'''
        conn = self.connection()
        return _gce_do(conn.networks().get, project=self.network_project_id, network=self.network_id)

    def _get_subnetworks(self, region=None):
        '''Get the subnetworks from the network object

            Arguments:
                region (str, optional): return only the subnetworks in the provided region
        '''
        network_data = self._get_network()
        if 'subnetworks' not in network_data:
            return []
        subnetworks = []
        conn = self.connection()
        for sn in network_data['subnetworks']:
            sn_region = sn.split('/')[-3]
            sn_name = sn.split('/')[-1]
            subnetwork = _gce_do(conn.subnetworks().get,
                            project=self.network_project_id,
                            region=sn_region, subnetwork=sn_name)
            subnetworks.append(subnetwork)
        if region:
            subnetworks = [_ for _ in subnetworks if _['region'].endswith(region)]
        return subnetworks

    def _get_metadata(self, instance, key):
        '''Retrieve the value of a key from the instance metadata

            Arguments:
                instance (obj): backend instance object
                key (str): key to lookup

            Returns: value or None
        '''
        if 'items' not in instance['metadata']:
            return None

        items       = instance['metadata']['items']
        try:
            value = [i['value'] for i in items if i['key'] == key][0]
            log.debug("Fetched metadata {}={}".format(key, value))
            return value
        except Exception:
            log.debug("No such metadata key:{}".format(key))
            return None

    def _delete_metadata(self, instance, key):
        '''Delete a key from the instance metadata and sync with the backend

            Arguments:
                instance (obj): backend instance object
                key (str): key to delete
        '''
        if 'items' not in instance['metadata']:
            return

        conn        = self.connection()
        metadata    = instance['metadata']
        zone        = instance['zone'].split('/')[-1]
        items       = metadata['items']
        existing = [ idx for idx, i in enumerate(items) if i['key'] == key]
        if existing:
            del metadata['items'][existing[0]]
        response = _gce_do(conn.instances().setMetadata,
                    project=self.project_id,
                    zone=zone,
                    instance=instance['name'],
                    body=metadata)
        self._wait_for_operation(response, msg='metadata to be deleted', zone=zone)

    def _set_metadata(self, instance, key, value):
        '''Set a key from the instance metadata and sync with the backend

            Arguments:
                instance (obj): backend instance object
                key (str): key to set
                value (str): value of key
        '''
        if 'items' not in instance['metadata']:
            instance['metadata']['items'] = []
        conn        = self.connection()
        zone        = instance['zone'].split('/')[-1]
        metadata    = instance['metadata']
        items       = metadata['items']
        existing = [ (idx, i['value']) for idx, i in enumerate(items) if i['key'] == key]
        if existing:
            idx, oldvalue = existing[0]
            metadata['items'][idx]['value'] = value
            log.debug("Updated metadata key:{}={} (from {})".format(key, value, oldvalue))
        else:
            metadata['items'].append(dict(key=key, value=value))
            log.debug("Setting metadata key:{}={}".format(key, value))

        response = _gce_do(conn.instances().setMetadata,
                    project=self.project_id,
                    zone=zone,
                    instance=instance['name'],
                    body=metadata)
        self._wait_for_operation(response, msg='metadata to be set', zone=zone)

    def valid_bucketname(self, name):
        '''Validate the instance name

            Returns: bool
        '''
        if not ServiceBase.valid_bucketname(self, name):
            return False
        if name.startswith('goog'):
            return False

        disallowed = ['google', 'gogle', 'googgle', 'g00gle', 'goog1e']
        if all([s not in name for s in disallowed]):
            return True

        return False

    def valid_instancename(self, name):
        '''Validate the instance name

            Returns: bool
        '''
        if not ServiceBase.valid_instancename(self, name):
            return False
        if len(name) > 63 or len(name) < 1:
            return False
        if self.INSTANCENAME_RE.match(name):
            return True
        return False

    def _zone_machine_types(self):
        '''Get a mapping of zones and their supported machine types
            Returns: dict zone:[types]
        '''
        response = _gce_do(self.connection().machineTypes().aggregatedList, project=self.project_id)
        return {zone_name.split('/')[1]: [mt['name'] for mt in zone_data.get('machineTypes', [])] for zone_name, zone_data in response['items'].items()}

    def _zone_names(self, all_regions=True):
        '''Get a list of zone names
            Arguments:
                all_regions (bool, optional): return zones for all regions, True
            Returns: list
        '''
        if not hasattr(self.local, '_zone_names'):
            conn = self.connection()
            self.local._zone_names = [_ for _ in self.zones]
            regions = _gce_do(conn.regions().list, project=self.project_id)['items']
            all_zones = [zone.split('/')[-1] for region in regions if 'zones' in region for zone in region['zones']]
            self.local._zone_names.extend([_ for _ in all_zones if _ not in self.zones])
        if all_regions:
            return self.local._zone_names
        else:
            region = self._zone_to_region(self.zones[0])
            return [_ for _ in self.local._zone_names if _.startswith(region)]

    def _zone_to_region(self, zone):
        '''Return the name of the region for a given zone

            This is typically just zone[:-2]

            Arguments:
                zone (str): name of the zone
        '''
        conn = self.connection()
        regions = _gce_do(conn.regions().list, project=self.project_id)['items']
        for r in regions:
            zone_url = '{}/{}/zones/{}'.format(self.GCE_URL, self.project_id, zone)
            if zone_url in r.get('zones', []):
                return r['name']
        raise vFXTConfigurationException("Invalid zone: {}".format(zone))

    def _gs_get_object(self, bucket, obj, fh, chunksize=1024 * 1024):
        '''Fetch an object from a bucket
            Arguments:
                bucket (str): bucket name
                obj (str): object name
                fh: filehandle (any io.IOBase derived filehandle, even StringIO
                chunksize: size of download chunks
        '''
        log.debug("Fetching {} from bucket {}".format(obj, bucket))
        c = self.connection(connection_type='storage')
        req = c.objects().get_media(bucket=bucket, object=obj)
        downloader = googleapiclient.http.MediaIoBaseDownload(fh, req, chunksize)

        done = False
        errors = 0
        while not done:
            try:
                status, done = downloader.next_chunk()
                if status:
                    log.debug("{:>3}% of {} downloaded".format(status.progress() * 100, obj))
            except googleapiclient.http.HttpError as e:
                if int(e.resp['status']) < 500:
                    raise vFXTServiceFailure("Failed to fetch object {}: {}".format(obj, e))
                errors += 1
                time.sleep(backoff(errors))
            except Exception as e:
                errors += 1
                time.sleep(backoff(errors))

    def _gs_fetch(self, url, filename):
        '''Retrieve the object from google storage, writing it to the passed in file location
            Arguments:
                url (str): gs:// url
                filename (str): name of destination file (absolute path)

            Returns: Nothing

            Raises:
            googleapiclient.errors.HttpError
        '''
        bkt = None
        obj = None

        log.debug("Fetching {} to {}".format(url, filename))
        try:
            m = self.GSURL_RE.match(url)
            if not m:
                raise Exception('Match failed')
            bkt = m.groups()[0]
            obj = m.groups()[1]
            if not bkt and obj:
                raise Exception('Both bucket and object not parsed')
        except Exception as e:
            log.debug("Failed parsing google storage url: {}".format(e))
            raise vFXTConfigurationException("Invalid google storage URL: {}".format(url))

        sig_file = filename + '.sig'
        sig_obj  = obj + '.sig'

        try:
            # does sig exist
            if os.access(sig_file, os.F_OK) and os.access(filename, os.F_OK):
                tmp = sig_file + '.tmp'
                with open(tmp, 'w') as f:
                    self._gs_get_object(bkt, sig_obj, f)
                sig_cmp = filecmp.cmp(sig_file, tmp)
                os.unlink(tmp)
                if sig_cmp: # we got it
                    log.debug("Signature {} up to date".format(sig_obj))
                    return # bail, nothing to be done
        except googleapiclient.errors.HttpError:
            pass

        # fetch sig for future comparison
        try:
            with open(sig_file, 'w') as f:
                self._gs_get_object(bkt, sig_obj, f)
        except Exception as e:
            log.debug(e)
            try:
                os.unlink(sig_file)
            except Exception as cleanup_e:
                log.debug("Failed to cleanup {}: {}".format(sig_file, cleanup_e))

        # get the actual file
        try:
            with open(filename, 'w') as f:
                self._gs_get_object(bkt, obj, f)
        except Exception as e:
            log.debug(e)
            try:
                os.unlink(filename)
            except Exception as cleanup_e:
                log.debug("Failed to cleanup {}: {}".format(filename, cleanup_e))
            raise

    def _destroy_installation_image(self, image):
        '''Destroy an installation image

            Arguments:
            name (str): name of the cloud image
        '''
        log.info("Destroying image {}".format(image))
        try:
            r = _gce_do(self.connection().images().delete, project=self.project_id, image=image)
            self._wait_for_operation(r, msg='image to be deleted', op_type='globalOperations')
        except Exception as e:
            raise vFXTServiceFailure("Failed to destroy image {}: {}".format(image, e))

    def add_instance_address(self, instance, address, **options):
        '''Add a new route to the instance

            Arguments:
                instance: backend instance
                address (str): IP address
                allow_reassignment (bool, optional): defaults to True
                priority (int, optional): priority (lower value is higher), defaults to 900

        '''
        conn = self.connection()
        addr = Cidr('{}/32'.format(address)) # validates
        dest = '{}/32'.format(addr.address)
        zone = instance['zone'].split('/')[-1]
        network = self._get_network()

        try:
            # need to check network/subnetwork ranges, if this address falls within those ranges
            # we can use the ip alias feature... otherwise we fall back to the route approach.
            ipalias_ranges = []
            subnetwork = None
            if self.subnetwork_id:
                subnetwork = self._get_subnetwork(self.subnetwork_id)
            if not subnetwork:
                subnetwork_region = self._zone_to_region(zone)
                subnetworks = [_ for _ in self._get_subnetworks(subnetwork_region)]
                if subnetworks: # no subnetwork specified, but we have them so use one
                    subnetwork = subnetworks[0]
            if subnetwork:
                if 'ipCidrRange' in subnetwork:
                    ipalias_ranges.append(subnetwork.get('ipCidrRange'))
                for subrange in subnetwork.get('secondaryIpRanges', []):
                    if 'ipCidrRange' in subrange:
                        ipalias_ranges.append(subrange.get('ipCidrRange'))

            if any([Cidr(_).contains(address) for _ in ipalias_ranges]):
                nic = instance['networkInterfaces'][0] # XXX only care about the first iface
                aliases = nic.get('aliasIpRanges', [])
                if dest in [_['ipCidrRange'] for _ in aliases]:
                    raise vFXTConfigurationException("Address already assigned: {}".format(address))

                aliases.append({'ipCidrRange': dest})
                nic['aliasIpRanges'] = aliases

                other_instance = self._who_has_ip(address)
                if other_instance:
                    log.debug("{} has {}, removing".format(other_instance['name'], address))
                    self.remove_instance_address(other_instance, address)

                log.debug('Adding instance address body {}'.format(nic))
                resp = _gce_do(conn.instances().updateNetworkInterface, instance=instance['name'], project=self.project_id, zone=zone, networkInterface=nic['name'], body=nic)
                self._wait_for_operation(resp, msg='IP Alias configuration', zone=zone)

            else: # XXX or fall back to routes
                # check for existing
                dest_filter = 'destRange eq {}'.format(dest)
                resp = _gce_do(conn.routes().list, project=self.network_project_id, filter=dest_filter)
                if 'items' in resp:
                    existing = resp['items']
                    network_selflink = network['selfLink']
                    # if we are the next hop instance for a route in our current network
                    if instance['selfLink'] in [_['nextHopInstance'] for _ in existing if _['network'] == network_selflink and 'nextHopInstance' in _]:
                        raise vFXTConfigurationException("Instance already has a route for this address: {}".format(dest))
                    if not options.get('allow_reassignment', True):
                        raise vFXTConfigurationException("Route already assigned: {}".format(existing))

                    for route in existing:
                        log.debug("Deleting route {}".format(route['name']))
                        resp = _gce_do(conn.routes().delete, project=self.network_project_id, route=route['name'])
                        self._wait_for_operation(resp, msg='route to be deleted', op_type='globalOperations')

                # add the route
                body = {
                    'name': '{}-{}'.format(self.name(instance), addr.address.replace('.','-')),
                    'network': network['selfLink'],
                    'nextHopInstance': instance['selfLink'],
                    'destRange': dest,
                    'priority': options.get('priority') or 900,
                }
                log.debug('Adding instance address body {}'.format(body))
                resp = _gce_do(conn.routes().insert,project=self.network_project_id, body=body)
                self._wait_for_operation(resp, msg='route to be created', op_type='globalOperations')
        except vFXTConfigurationException as e:
            raise
        except Exception as e:
            raise vFXTServiceFailure("Failed to add address: {}".format(e))

    def remove_instance_address(self, instance, address):
        '''Remove an instance route address

            Arguments:
                instance: backend instance
                address (str): IP address

            Raises: vFXTServiceFailure
        '''
        conn = self.connection()
        addr = Cidr('{}/32'.format(address)) # validates
        dest = '{}/32'.format(addr.address)
        zone = instance['zone'].split('/')[-1]

        try:
            nic = instance['networkInterfaces'][0]
            aliases = nic.get('aliasIpRanges', [])
            if dest not in [_['ipCidrRange'] for _ in nic.get('aliasIpRanges', [])]:
                # XXX or fall back on routes
                expr = 'destRange eq {}'.format(dest)
                routes = _gce_do(conn.routes().list, project=self.network_project_id,filter=expr)
                if not routes or 'items' not in routes:
                    #raise vFXTConfigurationException("No route was found for {}".format(addr.address))
                    raise vFXTConfigurationException("Address not assigned via routes: {}".format(address))
                for route in routes['items']:
                    if instance['selfLink'] != route['nextHopInstance']:
                        log.warning("Skipping route destined for other host: {} -> {}".format(address, route['nextHopInstance']))
                        continue
                    log.debug("Deleting route {}".format(route['name']))
                    resp = _gce_do(conn.routes().delete, project=self.network_project_id, route=route['name'])
                    self._wait_for_operation(resp, msg='route to be deleted', op_type='globalOperations')
                return
            # prune the ip aliases
            nic['aliasIpRanges'] = [_ for _ in aliases if _['ipCidrRange'] != dest]
            resp = _gce_do(conn.instances().updateNetworkInterface, instance=instance['name'], project=self.project_id, zone=zone, networkInterface=nic['name'], body=nic)
            self._wait_for_operation(resp, msg='IP Alias configuration', zone=zone)
        except vFXTConfigurationException as e:
            raise
        except Exception as e:
            raise vFXTServiceFailure("Failed to remove address: {}".format(e))

    def instance_in_use_addresses(self, instance, category='all'):
        '''Get the in use addresses for the instance

            Arguments:
                instance: backend instance
                category (str): all, instance, routes

            To obtain the public instance address, use 'public' category.  This
            is not included with 'all'.
        '''
        addresses = set()
        if category in ['all', 'instance']:
            for interface in instance['networkInterfaces']:
                interface_address = interface.get('networkIP')
                if interface_address:
                    addresses.add(interface_address)
                if 'aliasIpRanges' in interface:
                    ip_aliases = interface.get('aliasIpRanges')
                    for ip_alias in ip_aliases:
                        # we don't need to support ranges here... that just means they are auto assigned
                        # and not a specific address
                        # addresses.update(set(Cidr.expand_address_range(cidr_alias.start_address(), cidr_alias.end_address())))
                        if '/' in ip_alias['ipCidrRange'] and ip_alias['ipCidrRange'].split('/')[-1] != '32':
                            continue
                        addresses.add(ip_alias['ipCidrRange'].split('/')[0])

        if category in ['all', 'routes']:
            search = 'nextHopInstance eq .*/{}'.format(instance['name'])
            conn   = self.connection()
            resp   = _gce_do(conn.routes().list, project=self.network_project_id, filter=search)
            if resp and 'items' in resp:
                network_selflink = self._get_network()['selfLink']
                for route in resp['items']:
                    addr = route['destRange'].split('/')[0]
                    if addr == '0.0.0.0': # gw/default
                        continue
                    # if this route is for a different network, ignore it
                    if route['network'] != network_selflink:
                        continue
                    addresses.add(addr)

        # for special requests
        if category == 'public':
            for interface in instance['networkInterfaces']:
                try:
                    nat_addresses = [_['natIP'] for _ in interface['accessConfigs']]
                    addresses.update(set(nat_addresses))
                except Exception:
                    pass

        return list(addresses)

    def _add_tag(self, instance, tag):
        '''Add a tag to an instance
        '''
        conn     = self.connection()
        zone     = instance['zone'].split('/')[-1]
        instance = self.refresh(instance)
        tags = instance['tags']
        if 'items' not in tags:
            tags['items'] = []

        tags['items'].append(tag)

        response = _gce_do(conn.instances().setTags,
                    project=self.project_id,
                    zone=zone,
                    instance=instance['name'],
                    body=tags)
        self._wait_for_operation(response, msg='tags to be set', zone=zone)

    def _remove_tag(self, instance, tag):
        '''Remove a tag from an instance
        '''
        conn     = self.connection()
        zone     = instance['zone'].split('/')[-1]
        instance = self.refresh(instance)
        tags = instance['tags']
        if 'items' not in tags:
            tags['items'] = []

        if tag not in tags['items']:
            return
        tags['items'] = [_ for _ in tags['items'] if _ != tag]

        response = _gce_do(conn.instances().setTags,
                    project=self.project_id,
                    zone=zone,
                    instance=instance['name'],
                    body=tags)
        self._wait_for_operation(response, msg='tags to be set', zone=zone)

    def _cache_to_disk_config(self, cache_size, machine_type=None, disk_type=None): #pylint: disable=unused-argument
        '''For a given cache size, output the default data disk count and size

            Arguments:
                cache_size (int): vFXT cluster node cache size in GB
                machine_type (str, optional): vFXT cluster node machine type
                disk_type (str, optional): vFXT cluster node disk type

            Returns:
                tuple (disk count, size per disk)
        '''
        if disk_type == 'local-ssd':
            if cache_size > 3000: # 375GB max 8 disks
                raise vFXTConfigurationException("{} is larger than 3000GB, the maximum size for local-ssd disks".format(cache_size))
            count = int(cache_size / 375)
            if (cache_size % 375) != 0:
                count += 1
            return (count, 375)
        return tuple([1, cache_size])

    def _get_default_image(self):
        '''Get the default image from the defaults

            This may not be available if we are unable to fetch the defaults.
        '''
        try:
            return self.defaults['machineimages']['current']
        except Exception:
            raise vFXTConfigurationException("You must provide a root disk image.")

    def _disable_disk_auto_delete(self, instance, disk_name):
        '''Disable disk auto delete flag

            Arguments:
                instance: backend instance
                disk_name (str): disk name
        '''
        conn = self.connection()
        instance_zone = instance['zone'].split('/')[-1]
        op = _gce_do(conn.instances().setDiskAutoDelete,
                project=self.project_id,
                zone=instance_zone,
                instance=instance['name'],
                deviceName=disk_name,
                autoDelete=False)
        self._wait_for_operation(op, msg='auto delete attribute to be disabled', zone=instance_zone)

    def _get_subnetwork(self, subnetwork):
        '''Get the labeled subnetwork

            Arguments:
            subnetwork (str): subnetwork identifier

            This must be in one of the following form:
            "foo"
            "projects/project-foo/regions/us-east1/subnetworks/foo"
        '''
        if not subnetwork:
            raise vFXTConfigurationException("You must specify a subnetwork name")
        parts = subnetwork.split('/')
        if len(parts) not in [1, 6]:
            raise vFXTConfigurationException("Invalid subnetwork name: {}".format(subnetwork))

        conn = self.connection()
        try:
            if len(parts) == 1:
                subnetwork_region = self._zone_to_region(self.zones[0])
                subnetworks = [_ for _ in self._get_subnetworks(subnetwork_region) if _['name'] == subnetwork]
                if not subnetworks:
                    raise Exception('No such subnetwork')
                return subnetworks[0]
            elif len(parts) == 6:
                project = parts[1]
                region  = parts[3]
                name    = parts[5]
                return _gce_do(conn.subnetworks().get, project=project, region=region, subnetwork=name)
            else:
                raise Exception("Unknown subnetwork configuration")
        except Exception as e:
            log.debug("Failed to find subnetwork {}: {}".format(subnetwork, e))
            raise vFXTConfigurationException("Failed to find subnetwork {}: {}".format(subnetwork, e))

    def _who_has_ip(self, address):
        '''Helper to determine which instance owns a particular IP address
        '''
        conn = self.connection()

        # NOTE this has to iterate through all of the instances and examine the network interface
        # ip addresses (or associated routes if the address does not fall within the
        # network).  Awaiting a better API for this, see
        # https://issuetracker.google.com/issues/35905011
        # https://issuetracker.google.com/issues/73455339

        # lookup is instance if the address is not a routeable address, otherwise we also query routes with all
        category = 'instance' if self._cidr_overlaps_network('{}/32'.format(address)) else 'all'

        # look in all zones in the current region, starting with our current zones
        zones = [_ for _ in self.zones]
        for zone in self._zone_names(all_regions=False):
            if zone not in zones:
                zones.append(zone)
        for zone in zones:
            page_token = None
            while True:
                try:
                    r = _gce_do(conn.instances().list, project=self.project_id, zone=zone, pageToken=page_token)
                    if not r or 'items' not in r:
                        break
                    for instance in r['items']:
                        if address in self.instance_in_use_addresses(instance, category):
                            return instance
                    page_token = r.get('nextPageToken')
                    if not page_token:
                        break
                except Exception as e:
                    log.debug("_who_has_ip instance fetch failed: {}".format(e))
                    break
        return None

    def _get_network_project(self):
        if self.project_id:
            xpn_project = _gce_do(self.connection().projects().getXpnHost, project=self.project_id).get('name')
            if xpn_project:
                log.debug("Using {} for network project".format(xpn_project))
                return xpn_project
            return self.project_id
        else:
            return None

def _gce_do(f, retries=ServiceBase.CLOUD_API_RETRIES, **options):
    '''GCE function call wrapper with variable retries
        Arguments:
            f (function): function to call
            retries (int, optional): number of retries
            **options: options to pass to the function

        Returns: Returns the function call

        Raises: vFXTServiceFailure, vFXTServiceTimeout
    '''
    errors = 0
    while True:
        try:
            return f(**options).execute()
        except googleapiclient.errors.HttpError as e:
            if int(e.resp['status']) < 500:
                raise vFXTServiceFailure(e)
            errors += 1
            time.sleep(backoff(errors))
            if retries == 0:
                raise vFXTServiceTimeout('{} failed, exhausted retries: {}'.format(f.__name__, e))
        except Exception as e:
            log.debug("Unknown GCE retry-able function call failure: {}".format(e))
        retries -= 1
        if retries == 0:
            raise vFXTServiceTimeout('{} failed, exhausted retries: {}'.format(f.__name__, e))
        time.sleep(Service.POLLTIME)
