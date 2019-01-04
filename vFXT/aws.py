# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
''' Abstraction for doing things on instances via Amazon

Cookbook/examples:

aws = vFXT.aws.Service(region='', subnet='', access_key='', secret_access_key='')
# or if on an AWS instance, we can autodetect settings
aws = vFXT.aws.Service.on_instance_init()

# Connection factory, has a thread specific copy
connection = aws.connection()
s3 = aws.connection(connection_type='s3')
iam = aws.connection(connection_type='iam')
vpc = aws.connection(connection_type='vpc')

instances = aws.find_instances({}) # filter dictionary
instances = aws.get_instances([])

instance = aws.get_instance('instance id')
aws.start(instance)
aws.stop(instance)
aws.restart(instance)
aws.destroy(instance)

aws.shelve(instance)
aws.unshelve(instance)

instance = aws.refresh(instance)

print aws.name(instance)
print aws.ip(instance)
print aws.fqdn(instance)
print aws.status(instance)

if aws.is_on(instance): pass
if aws.is_off(instance): pass
if aws.is_shelved(instance): pass

aws.wait_for_status(instance, aws.ON_STATUS, retries=aws.WAIT_FOR_STATUS)
aws.wait_for_service_checks(instance, retries=aws.WAIT_FOR_SERVICE_CHECKS)

aws.create_instance(machine_type, name, boot_disk_image, other_disks=None, tags=None, **options)
aws.create_cluster(self, cluster, **options)

aws.create_bucket(name)
aws.delete_bucket(name)

aws.load_cluster_information(cluster)

ip_count = 10
ip_addresses, netmask = aws.get_available_addresses(count=ip_count, contiguous=True)
aws.get_dns_servers(subnet_id)
aws.get_ntp_servers(subnet_id)
aws.get_default_router(subnet_id)

serializeme = aws.export()
newaws = vFXT.aws.Service(**serializeme)
'''

import threading
import Queue
import re
import os
import time
import logging
import socket
import json
import urllib2
import filecmp
from itertools import cycle

import boto
import boto.ec2
import boto.vpc
import boto.s3
import boto.s3.connection
import boto.iam
import boto.utils
logging.getLogger('boto').setLevel(logging.CRITICAL)

from vFXT.cidr import Cidr
from vFXT.serviceInstance import ServiceInstance
from vFXT.service import *

log = logging.getLogger(__name__)

s3_region_locations = {
    'us-east-1':        boto.s3.connection.Location.DEFAULT,
    'us-east-2':        'us-east-2',
    'eu-west-1':        boto.s3.connection.Location.EU,
    'us-west-1':        boto.s3.connection.Location.USWest,
    'us-west-2':        boto.s3.connection.Location.USWest2,
    'sa-east-1':        boto.s3.connection.Location.SAEast,
    'ap-northeast-1':   boto.s3.connection.Location.APNortheast,
    'ap-northeast-2':   'ap-northeast-2',
    'ap-southeast-1':   boto.s3.connection.Location.APSoutheast,
    'ap-southeast-2':   boto.s3.connection.Location.APSoutheast2,
    'ap-south-1':       'ap-south-1',
    'cn-north-1':       boto.s3.connection.Location.CNNorth1,
}

class Service(ServiceBase):
    '''AWS Service backend'''
    ON_STATUS = "running"
    OFF_STATUS = "stopped"
    PENDING_STATUS = 'pending'
    DESTROY_STATUS = "terminated"
    NTP_SERVERS = ['169.254.169.123']
    DNS_SERVERS = []
    MACHINE_DEFAULTS = {
        "t2.micro":     {"data_disk_count": 1, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
        "t2.small":     {"data_disk_count": 1, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
        "t2.large":     {"data_disk_count": 1, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
        "m1.small":     {"data_disk_count": 1, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
        "c3.xlarge":    {"data_disk_count": 8, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "c3.2xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "c3.4xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "c3.8xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
        "c4.xlarge":    {"data_disk_count": 8, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "c4.2xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "c4.4xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "c4.8xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r3.xlarge":    {"data_disk_count": 8, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r3.2xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r3.4xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r3.8xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
        "r4.2xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r4.4xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r4.8xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": True, "node_count": 3},
        "r4.16xlarge":   {"data_disk_count": 10, "data_disk_size": "200", 'data_disk_type': 'gp2', "ebsoptimized": False, "node_count": 3},
    }
    MACHINE_TYPES = MACHINE_DEFAULTS.keys()
    DEFAULTS_URL = "http://avere-dist.s3-website-us-west-2.amazonaws.com/vfxtdefaults.json"
    S3TYPE_NAME = 'AMAZON'
    COREFILER_TYPE = 's3'
    COREFILER_CRED_TYPE = 's3'
    INSTANCENAME_RE = re.compile(r'[a-zA-Z0-9\ \t\+\-=\._:\/@]+$')
    ARN = "aws"
    IAM_HOST = 'iam.amazonaws.com'
    IAM_ROLE_PRINCIPAL_SERVICE = 'ec2.amazonaws.com'
    AWS_INSTANCE_HOST = '169.254.169.254'
    S3URL_RE = re.compile(r's3://(?P<bucket>[^\/]*)/(?P<path>.*)$')
    IAM_BUCKET_POLICY = ['s3:GetLifecycleConfiguration',
                       's3:GetBucketLocation',
                       's3:ListBucket',
                       's3:ListBucketMultipartUploads',
                       's3:ListBucketVersions',
                       's3:PutLifecycleConfiguration']
    IAM_OBJECT_POLICY = ['s3:AbortMultipartUpload',
                       's3:DeleteObject',
                       's3:GetObject',
                       's3:ListMultipartUploadParts',
                       's3:PutObject']
    IAM_OBJECT_POLICY_WRITE_ONLY = ['s3:AbortMultipartUpload',
                       's3:ListMultipartUploadParts',
                       's3:PutObject']
    IAM_POLICY = ['ec2:AssignPrivateIpAddresses',
                'ec2:UnassignPrivateIpAddresses',
                'ec2:DescribeInstance*',
                'ec2:DescribeRouteTables',
                'ec2:DescribeSubnets',
                'ec2:ReplaceRoute',
                'ec2:CreateRoute',
                'ec2:DeleteRoute']
    ENDPOINT_TEST_HOSTS = ['s3.amazonaws.com']
    BOTO_503_RETRIES = 10
    CREATE_INSTANCE_IAM_PROPAGATION_RETRIES = 60
    ALLOCATE_INSTANCE_ADDRESSES = True
    OFFLINE_DEFAULTS = {
        'version': '1',
        'clustermanager': {
            'instanceTypes': [ 'r3.2xlarge', 'r3.8xlarge' ],
            'maxNumNodes': 20,
            'cacheSizes': [
                { 'size': 250, 'type': 'gp2', 'label': '250' },
                { 'size': 1000, 'type': 'gp2', 'label': '1000' },
                { 'size': 4000, 'type': 'gp2', 'label': '4000' },
                { 'size': 8000, 'type': 'gp2', 'label': '8000' }
            ]
        }
    }

    def __init__(self, region, access_key, secret_access_key, **options):
        '''Constructor
            This performs an initial connection test and downloads the default
            data.

            If using a different S3 account, the S3 credentials can be provided
            long with the AWS credentials.

            Arguments:
                region (str): AWS region
                access_key (str): account access key
                secret_access_key (str): secret access key
                subnet (str or []): one or more subnets
                profile_name (str, optional): AWS profile name
                s3_access_key (str, optional): S3 account to use instead
                s3_secret_access_key (str, optional): S3 account to use instead
                s3_profile_name (str, optional): S3 profile name
                arn (str, optional): defaults to aws
                iam_host (str, optional): custom IAM host
                iam_role_principal_service (str, optional): custom IAM role principal service hostname
                security_token (str, optional): AWS security token
                private_range (str, optional): private address range (cidr)
                security_groups (str, optional): default security groups

                proxy_uri (str, optional): URI of proxy resource (e.g. http://user:pass@172.16.16.20:8080)

                no_connection_test (bool, optional): skip connection test
                skip_load_defaults (bool, optional): do not fetch defaults
        '''
        super(Service, self).__init__()
        self.region               = region
        self.access_key           = access_key
        self.secret_access_key    = secret_access_key

        self.subnets              = options.get('subnet', None)
        self.profile_name         = options.get('profile_name', None)
        self.s3_access_key        = options.get('s3_access_key') or self.access_key
        self.s3_secret_access_key = options.get('s3_secret_access_key') or self.secret_access_key
        self.s3_profile_name      = options.get('s3_profile_name') or self.profile_name
        self.arn                  = options.get('arn') or self.ARN
        self.iam_host             = options.get('iam_host') or self.IAM_HOST
        self.iam_role_principal_service = options.get('iam_role_principal_service') or self.IAM_ROLE_PRINCIPAL_SERVICE
        self.security_token       = options.get('security_token', None)
        self.private_range        = options.get('private_range', None)
        self.proxy_uri            = options.get('proxy_uri', None)
        self.security_groups      = options.get('security_groups', None)
        self.on_instance          = options.get('on_instance') or False
        self.source_address       = options.get('source_address') or False

        if not self.subnets:
            raise vFXTConfigurationException("You must provide at least one subnet")

        self.subnets = [self.subnets] if isinstance(self.subnets, basestring) else self.subnets
        self.security_groups = self.security_groups.split(' ') if isinstance(self.security_groups, basestring) else self.security_groups

        if self.proxy_uri:
            self.set_proxy(self.proxy_uri)

        # emit third party library version information
        log.debug("Using boto version {}".format(boto.__version__))

        if not options.get('no_connection_test', None):
            self.connection_test()

        if not options.get('skip_load_defaults', False):
            log.debug("Fetching defaults from {}".format(self.DEFAULTS_URL))
            load_defaults(self)

    @classmethod
    def get_instance_data(cls, source_address=None):
        '''Detect the instance data
            Arguments:
                source_address (str, optional): source address for data request

            This only works when running on an AWS instance.

            This is a service specific data structure.

            Well known keys that can be expected across services:
            machine_type (str): machine/instance type
            account_id (str): account identifier
            service_id (str): unique identifier for this host
            ssh_keys ([str]): ssh keys
            cluster_cfg (str): cluster configuration

            Raises vFXTServiceFailure
        '''
        import httplib

        data = {}
        attributes = ['ami-id', 'ami-launch-index', 'ami-manifest-path',
                    'hostname', 'instance-action', 'instance-id', 'instance-type',
                    'local-hostname', 'local-ipv4', 'mac', 'profile', 'reservation-id',
                    'security-groups', 'placement/availability-zone', 'public-keys/0/openssh-key']
        mac_attrs = ['device-number', 'interface-id', 'local-hostname',
                    'local-ipv4s', 'mac', 'owner-id', 'security-group-ids',
                    'security-groups', 'subnet-id', 'subnet-ipv4-cidr-block',
                    'vpc-id', 'vpc-ipv4-cidr-block']

        if source_address:
            source_address = (source_address, 0)
        connection_host = cls.AWS_INSTANCE_HOST
        connection_port = httplib.HTTP_PORT

        conn = httplib.HTTPConnection(connection_host, connection_port, source_address=source_address, timeout=CONNECTION_TIMEOUT)

        try:

            for attr in attributes:
                conn.request('GET', '/latest/meta-data/{}'.format(attr))
                attr = attr.split('/')[-1] # flatten
                resp = conn.getresponse()
                if resp.status != 200:
                    data[attr] = ''
                    continue
                value = resp.read()
                try:
                    value = json.loads(value)
                except Exception:
                    if str(value).find('\n') > -1: # make a list of multi-values
                        value = str(value).split('\n')
                data[attr] = value

            conn.request('GET', '/latest/dynamic/instance-identity/document')
            resp = conn.getresponse()
            if resp.status == 200:
                data['document'] = json.loads(resp.read())

            conn.request('GET', '/latest/user-data')
            resp = conn.getresponse()
            data['user-data'] = ''
            if resp.status == 200:
                data['user-data'] = resp.read()

            data['network'] = {'interfaces': {'macs': {}}}
            conn.request('GET', '/latest/meta-data/network/interfaces/macs/')
            macs = []
            resp = conn.getresponse()
            if resp.status == 200:
                macs = [m[:-1] for m in resp.read().split('\n')]
            for mac in macs:
                attr_data = {}
                for attr in mac_attrs:
                    conn.request('GET', '/latest/meta-data/network/interfaces/macs/{}/{}'.format(mac, attr))
                    r = conn.getresponse().read()
                    try:
                        r = json.loads(r)
                    except Exception:
                        if str(r).find('\n') > -1:
                            r = str(r).split('\n')
                    attr_data[attr] = r
                data['network']['interfaces']['macs'][mac] = attr_data

            conn.request('GET', '/latest/meta-data/iam/security-credentials/')
            creds = []
            resp = conn.getresponse()
            if resp.status == 200:
                creds = resp.read().split('\n')
            data['iam'] = {'security-credentials': {}}
            for cred in creds:
                conn.request('GET', '/latest/meta-data/iam/security-credentials/{}'.format(cred))
                data['iam']['security-credentials'][cred] = json.loads(conn.getresponse().read())

            conn.request('GET', '/latest/meta-data/iam/info')
            resp = conn.getresponse()
            data['arn'] = None
            if resp.status == 200:
                try:
                    r = json.loads(resp.read())
                    data['arn'] = r['InstanceProfileArn'].split(':')[1]
                except Exception: pass

            data['region']      = data['document']['region']
            data['hostname']    = data['hostname'].split(' ')[0]
            data['machine_type'] = data['instance-type']
            data['account_id']  = data['document'].get('accountId', 'unknown')
            data['service_id']  = data['instance-id']
            data['ssh_keys']    = data['openssh-key'] if data['openssh-key'] else []
            data['cluster_cfg'] = data['user-data']

        except Exception as e:
            raise vFXTServiceMetaDataFailure('Unable to read instance metadata: {}'.format(e))
        finally:
            conn.close()

        return data

    @classmethod
    def environment_init(cls, profile='default', **kwargs):
        '''Init an AWS service object using the local environment credentials

            Arguments:
                profile (str, optional): authentication profile ('default')
                **kwargs: arguments passed through to __init__

            This tries to read credential information from the environment, either
            environment variables or via ~/.aws/credentials.

            Environment variables include AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
            and AWS_SECURITY_TOKEN.
        '''
        cred_config = boto.config.__class__(do_load=False)
        cred_path = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')
        cred_config.load_from_path(cred_path)

        access_key = os.environ.get('AWS_ACCESS_KEY_ID') or cred_config.get(profile, 'aws_access_key_id')
        secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY') or cred_config.get(profile, 'aws_secret_access_key')
        token      = os.environ.get('AWS_SECURITY_TOKEN') or cred_config.get(profile, 'aws_session_token')

        if not all([access_key, secret_key]):
            raise vFXTConfigurationException("Unable to read local credentials.  Try 'aws configure help'")
        log.debug("Read access key {} and secret key from local credentials".format(access_key))

        if not kwargs.get('region'):
            config_path = os.path.join(os.path.expanduser('~'), '.aws', 'config')
            cred_config.load_from_path(config_path)
            region = cred_config.get(profile, 'region')
            if not region:
                raise vFXTConfigurationException("Unable to read region.  Try 'aws configure help'")
            kwargs['region'] = region
            log.debug("Read region {} from local configuration".format(region))

        return Service(access_key=access_key, secret_access_key=secret_key, security_token=token, **kwargs)

    @classmethod
    def on_instance_init(cls, source_address=None, no_connection_test=False, proxy_uri=None, **options):
        '''Init an AWS service object from instance metadata
            Arguments:
                source_address (str, optional): source address for data request
                no_connection_test (bool, optional): skip connection tests, defaults to False
                proxy_uri (str, optional): URI of proxy resource

                access_key (str, optional): account access key
                secret_access_key (str, optional): secret access key
                security_token (str, optional): AWS security token
                skip_load_defaults (bool, optional): do not fetch defaults

            This is only meant to be called on instance.  Otherwise will
            raise a vFXTConfigurationException exception.

            If instance credentials are sparse, the connection test will also
            fail with permission error.  This is the case if the current instance
            is not started with an IAM role with PassRole.  In that case, credentials
            will need to be provided with the access_key, secret_access_key, and security_token
            options.

            http://docs.aws.amazon.com/IAM/latest/UserGuide/roles-usingrole-ec2instance.html
            http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
            http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
            http://docs.aws.amazon.com/STS/latest/UsingSTS/Welcome.html
        '''
        instance_data = cls.get_instance_data(source_address=source_address)
        log.debug('Read instance data: {}'.format(instance_data))
        try:

            region = instance_data['region']
            #vpc_id      = instance_data['network']['interfaces']['macs'].values()[0]['vpc-id']
            #instance_id = instance_data['instance-id']
            subnet_id   = instance_data['network']['interfaces']['macs'].values()[0]['subnet-id']
            arn   = instance_data['arn']
            security_groups = instance_data['network']['interfaces']['macs'].values()[0]['security-group-ids']

            if all([options.get(_) for _ in ['access_key', 'secret_access_key', 'security_token']]):
                access_key = options.get('access_key')
                secret_key = options.get('secret_access_key')
                token = options.get('security_token') or None
            else:
                if 'iam' not in instance_data or not instance_data['iam']['security-credentials']:
                    raise Exception('Cannot read IAM information.  Check role policy permissions')

                access_key = instance_data['iam']['security-credentials'].values()[0]['AccessKeyId']
                secret_key = instance_data['iam']['security-credentials'].values()[0]['SecretAccessKey']
                token = instance_data['iam']['security-credentials'].values()[0]['Token']

            iam_conn = boto.iam.connect_to_region(region, aws_access_key_id=access_key, aws_secret_access_key=secret_key, security_token=token)
            if not iam_conn:
                raise Exception("Unable to determine the IAM host. Check endpoint configuration.")
            iam_host = iam_conn.host

            srv = Service(region=region, access_key=access_key, secret_access_key=secret_key,
                          subnet=subnet_id, security_token=token, arn=arn, iam_host=iam_host,
                          no_connection_test=no_connection_test, proxy_uri=proxy_uri,
                          security_groups=security_groups, on_instance=True,
                          skip_load_defaults=options.get('skip_load_defaults'), source_address=source_address)
            srv.local.instance_data = instance_data
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

        # fail as fast as possible... boto does not make it easy
        boto_config = boto.config
        boto_config.has_section('Boto') or boto_config.add_section('Boto') #pylint: disable=expression-not-assigned
        exiting_timeout = boto_config.get('Boto', 'http_socket_timeout')
        exiting_retries = boto_config.get('Boto', 'num_retries')
        try:
            if not self.proxy: # proxy environments may block outgoing name resolution
                self.dns_check()

            boto_config.set('Boto', 'http_socket_timeout', str(CONNECTION_TIMEOUT))
            boto_config.set('Boto', 'num_retries', '0')
            conn = self.connection()
            conn.get_all_reservations(filters={'tag:invalid_tag': '. .'}) # invalid name for filter
        except Exception as e:
            log.debug(e)
            raise vFXTServiceConnectionFailure("Failed to establish connection to service: {}".format(e))
        finally:
            if exiting_timeout:
                boto_config.set('Boto', 'http_socket_timeout', exiting_timeout)
            else:
                boto_config.remove_option('Boto', 'http_socket_timeout')
            if exiting_retries:
                boto_config.set('Boto', 'num_retries', exiting_retries)
            else:
                boto_config.remove_option('Boto', 'num_retries')

    def check(self, percentage=0.6, instances=0, machine_type=None, data_disk_type=None, data_disk_size=None, data_disk_count=None): #pylint: disable=unused-argument
        '''Check quotas and API access

            Arguments:
            percentage (float, optional): percentage as a decimal
            instances (int, optional): Number of planned for instances to account for
            machine_type (str, optional): Machine type
            data_disk_type (str, optional): Data disk type
            data_disk_size (int, optional): Data disk size
            data_disk_count (int, optional): Data disk count
        '''
        conn = self.connection()

        try:
            log.info("Performing quota check")
            account_attributes = conn.describe_account_attributes()
            max_instances = filter(lambda x: x.attribute_name == 'max-instances', account_attributes)
            if not max_instances:
                raise vFXTServiceFailure("Failed to lookup max instance quota")
            max_count = int(max_instances[0].attribute_values[0])
            instance_count = len([i for r in conn.get_all_reservations() for i in r.instances]) + (instances or 0)
            if (instance_count + 0.0) / max_count > percentage:
                log.warn("QUOTA ALERT: Using {} of {} instances".format(instance_count, max_count))
            else:
                log.debug("Using {} of {} instances".format(instance_count, max_count))
        except Exception as e:
            log.error("Failed quota check: {}".format(e))

        log.info("Performing API tests")
        try:
            # ec2:DescribeInstance*
            conn.get_all_reservations(filters={'tag:invalid_tag': '. .'}) # invalid name for filter
            # ec2:DescribeRouteTables
            self._get_route_tables()
            # ec2:DescribeSubnets
            self._get_subnet(self.subnets[0])
        except Exception as e:
            log.error("Failed API test: {}".format(e))

        log.info("Performing IAM create/delete policy test")
        import uuid
        role_name = 'avere_iam_check_{}'.format(str(uuid.uuid4()).lower().replace('-', '')[0:63])
        role = None
        try:
            role = self._create_iamrole(role_name)
        except Exception as e:
            log.error("Failed to create IAM role {}: {}".format(role_name, e))
        if role:
            try:
                self._delete_iamrole(role['role_name'])
            except Exception as e:
                log.error("Failed to delete IAM role {}: {}".format(role_name, e))

        log.info("Performing S3 create/delete bucket test")
        bucket_name = str(uuid.uuid4()).lower().replace('-', '')[0:63]
        bucket = None
        try:
            bucket = self.create_bucket(bucket_name)
        except Exception as e:
            log.error("Failed to create bucket {}: {}".format(bucket_name, e))
        if bucket:
            try:
                self.delete_bucket(bucket.name)
            except Exception as e:
                log.error("Failed to delete bucket {}: {}".format(bucket_name, e))

    def connection(self, connection_type='ec2'):
        '''Connection factory, returns a new connection or thread local copy

            Arguments:
                connection_type (str, optional): connection type (ec2, s3, iam, vpc)
        '''
        try:
            cred_expiration = self.local.instance_data['iam']['security-credentials'].values()[0]['Expiration']
            if (int(time.mktime(time.strptime(cred_expiration, "%Y-%m-%dT%H:%M:%SZ"))) - 120) < int(time.time()):
                log.debug("Access token expired, forcing refresh")
                self.local.connections = {}
        except Exception: pass

        access_key           = self.access_key
        secret_access_key    = self.secret_access_key
        security_token       = self.security_token
        s3_access_key        = self.s3_access_key
        s3_secret_access_key = self.s3_secret_access_key

        if not hasattr(self.local, 'connections'):
            self.local.connections = {}
        if not self.local.connections.get(connection_type, False):
            # if we are on instance, get most up to date
            if self.on_instance:
                instance_data            = self.get_instance_data(source_address=self.source_address)
                if instance_data['iam'].get('security-credentials'):
                    creds                    = instance_data['iam']['security-credentials'].values()[0]
                    self.local.instance_data = instance_data
                    access_key               = creds['AccessKeyId']
                    secret_access_key        = creds['SecretAccessKey']
                    security_token           = creds['Token']
                    s3_access_key            = creds['AccessKeyId']
                    s3_secret_access_key     = creds['SecretAccessKey']

            proxy_settings = {}
            proxy_settings['proxy']      = self.proxy.hostname if self.proxy else None
            proxy_settings['proxy_port'] = self.proxy.port if self.proxy else None
            proxy_settings['proxy_user'] = self.proxy.username if self.proxy else None
            proxy_settings['proxy_pass'] = self.proxy.password if self.proxy else None

            log.debug("Creating new {} object".format(connection_type))
            err_fmt = 'Unable to create connection to {}: {}'
            if connection_type == 'ec2':
                newconn = boto.ec2.connect_to_region(self.region,
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_access_key,
                            profile_name=self.profile_name,
                            security_token=security_token, **proxy_settings)
                if not newconn:
                    raise vFXTServiceConnectionFailure(err_fmt.format('region', self.region))
            elif connection_type == 's3':
                newconn = boto.s3.connect_to_region(self.region,
                             aws_access_key_id=s3_access_key,
                             aws_secret_access_key=s3_secret_access_key,
                             profile_name=self.s3_profile_name,
                             security_token=security_token, **proxy_settings)
                if not newconn:
                    raise vFXTServiceConnectionFailure(err_fmt.format('region', self.region))
            elif connection_type == 'iam':
                newconn = boto.iam.connection.IAMConnection(
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_access_key,
                            profile_name=self.profile_name,
                            host=self.iam_host,
                            security_token=security_token, **proxy_settings)
                if not newconn:
                    raise vFXTServiceConnectionFailure(err_fmt.format('IAM host', self.iam_host))
            elif connection_type == 'vpc':
                newconn = boto.vpc.connect_to_region(self.region,
                            aws_access_key_id=access_key,
                            aws_secret_access_key=secret_access_key,
                            profile_name=self.profile_name,
                            security_token=security_token, **proxy_settings)
                if not newconn:
                    raise vFXTServiceConnectionFailure(err_fmt.format('region', self.region))
            else:
                raise vFXTConfigurationException("Unknown connection type: {}".format(connection_type))

            self.local.connections[connection_type] = newconn

        return self.local.connections[connection_type]

    def find_instances(self, search=None):
        '''Returns all or filtered list of instances

            Arguments:
                search (dict): search query

            Search examples:
                {"subnet_id":subnet_id}
                {"private_ip_address":['10.1.1.1','10.1.1.2']}
                {"tag:Name":"*lg*"}
                {"tag:Owner":"tstark"}
        '''
        conn = self.connection()
        return [i for r in _aws_do(conn.get_all_reservations, filters=search)
                for i in r.instances]

    def get_instances(self, instance_ids):
        '''Returns a list of instances with the given instance ID list

            Arguments:
                instance_ids ([str]): list of instance id strings

            Returns:
                [objs]: list of backend instance objects
        '''
        conn = self.connection()
        return [i for r in _aws_do(conn.get_all_reservations, instance_ids)
                for i in r.instances]

    def get_instance(self, instance_id):
        '''Get a specific instance by instance ID

            Arguments:
                instance_id (str)

            Returns:
                obj or None
        '''
        instances = self.get_instances([instance_id])
        if instances:
            return instances[0]
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
        while status != s:
            if retries % 10 == 0: # rate limit
                log.debug("Waiting for status: {} != {}".format(s, status))
            time.sleep(self.POLLTIME)
            try:
                s = _aws_do(instance.update)
            except Exception as e:
                log.debug('Ignored wait_for_status: {}'.format(e))
            retries -= 1
            if retries == 0:
                message = 'unknown'
                try:
                    message = instance.state_reason['message']
                except Exception: pass
                raise vFXTServiceTimeout("Timed out waiting for {} on {} ({})".format(status, instance.id, message))

    def wait_for_service_checks(self, instance, retries=ServiceBase.WAIT_FOR_SERVICE_CHECKS):
        '''Wait for Amazon service checks to complete

            Arguments:
                instance: backend instance
                retries (int, optional): numb of retries

            Raises: vFXTServiceTimeout
        '''
        log.info("Checking health checks for instance {}".format(instance.id))
        instance_id = instance.id
        conn        = self.connection()
        statuses    = _aws_do(conn.get_all_instance_status, instance_id)
        if not statuses:
            return
        status = statuses[0]
        instance.reboots_tried = getattr(instance, 'reboots', 0) # temp attribute
        while status.system_status.status != 'ok' and status.instance_status.status != 'ok':
            time.sleep(self.POLLTIME)
            retries -= 1
            if retries == 0:
                if instance.reboots_tried == 3:
                    raise vFXTServiceTimeout("Failed waiting for {} status checks".format(instance_id))
                else:
                    instance.reboots_tried += 1
                    log.debug("Attempt {} to restart instance {}".format(instance.reboots_tried, instance_id))
                    self.restart(instance)
            try:
                statuses = _aws_do(conn.get_all_instance_status, instance_id)
                if statuses:
                    status = statuses[0]
            except Exception as e:
                log.debug('Ignored wait_for_service_checks: {}'.format(e))

    def can_stop(self, instance):
        ''' Some instance configurations cannot be stopped. Check if this is one.

            Arguments:
                instance: backend instance
        '''
        if len(instance.block_device_mapping) == 1: # ephemeral
            return False
        return True

    def stop(self, instance, wait=ServiceBase.WAIT_FOR_STOP):
        '''Stop an instance

            Arguments:
                instance: backend instance
        '''
        log.info("Stopping instance {}".format(self.name(instance)))
        instance.stop()
        self.wait_for_status(instance, self.OFF_STATUS, wait)

    def start(self, instance, wait=ServiceBase.WAIT_FOR_START):
        '''Start an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
        '''
        log.info("Starting instance {}".format(self.name(instance)))
        instance.start()
        self.wait_for_status(instance, self.ON_STATUS, wait)

    def restart(self, instance, wait=ServiceBase.WAIT_FOR_RESTART):
        '''Restart an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
        '''
        log.info("Restarting instance {}".format(self.name(instance)))
        # use reboot so our instance state and billing isn't changed
        instance.reboot()
        self.wait_for_status(instance, self.ON_STATUS, wait)

    def destroy(self, instance, wait=ServiceBase.WAIT_FOR_DESTROY, keep_root_disk=False):
        '''Destroy an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
                keep_root_disk (bool, optional): keep the root disk
        '''
        if keep_root_disk:
            conn = self.connection()
            root_device = instance.root_device_name
            # this syntax for disabling delete on termination is odd... but that is how it is plumbed in boto
            conn.modify_instance_attribute(instance.id, "BlockDeviceMapping", ['{}=false'.format(root_device)])
            instance.update()

        # clean up any routes
        vpc = self.connection(connection_type='vpc')
        routes = [{'route_table_id': rt.id, 'destination_cidr_block': r.destination_cidr_block}
                    for rt in _aws_do(vpc.get_all_route_tables)
                    for r in rt.routes
                    if r.instance_id == instance.id]
        for route in routes:
            try:
                _aws_do_non_idempotent(vpc.delete_route, **route)
            except Exception as e:
                log.debug("Ignored delete route failure: {}".format(e))

        log.info("Destroying instance {}".format(self.name(instance)))
        _aws_do(instance.terminate)
        try:
            self.wait_for_status(instance, self.DESTROY_STATUS, wait)
        except Exception as e:
            log.warn(e)

    def is_on(self, instance):
        '''Return True if the instance is currently on

            Arguments:
                instance: backend instance

            This will be false if the instance is off or terminated.
        '''
        s = _aws_do(instance.update)
        return self.OFF_STATUS != s and self.DESTROY_STATUS != s

    def is_off(self, instance):
        '''Return True if the instance is currently off

            Arguments:
                instance: backend instance

            This will be true if the instance is on or terminated.
        '''
        s = _aws_do(instance.update)
        return self.OFF_STATUS == s or self.DESTROY_STATUS == s

    def is_shelved(self, instance):
        '''Return True if the instance is currently shelved

            Arguments:
                instance: backend instance
        '''
        return 'shelved' in instance.tags

    def name(self, instance):
        '''Returns the instance name (may be different from instance id)

            Arguments:
                instance: backend instance
        '''
        return instance.tags.get('Name', instance.id)

    def instance_id(self, instance):
        '''Returns the instance id (may be different from instance name)

            Arguments:
                instance: backend instance
        '''
        return instance.id

    def status(self, instance):
        '''Return the instance status

            Arguments:
                instance: backend instance
        '''
        return _aws_do(instance.update)

    def refresh(self, instance):
        '''Refresh the instance from the Amazon backend

            Arguments:
                instance: backend instance
        '''
        try:
            # get a fresh object since it has a copy of the actual connection inside
            # which may have expired credentials
            return self.get_instance(instance.id)
        except Exception as e:
            raise vFXTConfigurationException("Failed to find instance: {}".format(e))

    def ip(self, instance):
        '''Return the primary IP address of the instance

            Arguments:
                instance: backend instance
        '''
        return instance.private_ip_address

    def fqdn(self, instance):
        '''Provide the fully qualified domain name of the instance

            Arguments:
                instance: backend instance
        '''
        try:
            return socket.gethostbyaddr(instance.private_ip_address)[0]
        except Exception:
            return instance.private_dns_name

    # storage/buckets
    def create_bucket(self, name, **options):
        '''Create a bucket

            Arguments:
                name (str): bucket name to create
                tags (dict): tags to apply to the bucket

            Raises: vFXTServiceFailure
        '''
        if not self.valid_bucketname(name):
            raise vFXTConfigurationException("{} is not a valid bucket name".format(name))

        s3 = self.connection(connection_type='s3')

        # we support having 2 connections (if s3 account is different from ec2
        ec2_grant_user = None
        if self.s3_access_key != self.access_key:
            ec2s3 = boto.s3.connection.S3Connection(self.access_key, self.secret_access_key,
                    security_token=self.security_token)
            ec2_grant_user = _aws_do(ec2s3.get_canonical_user_id)

        # tagging
        btags  = boto.s3.tagging.Tags()
        tagset = boto.s3.tagging.TagSet()
        tags = options.get('tags', {})
        if tags:
            for k, v in tags.iteritems():
                tagset.add_tag(k, v)
            tagset.add_tag('Name', name)
            btags.add_tag_set(tagset)


        s3_region = s3_region_locations[self.region] if self.region in s3_region_locations else self.region

        retries = ServiceBase.CLOUD_API_RETRIES
        while True:
            try:
                b = _aws_do_non_idempotent(s3.create_bucket, name, location=s3_region)
                if ec2_grant_user:
                    log.info("Granting EC2 user bucket control")
                    _aws_do(b.add_user_grant, 'FULL_CONTROL', ec2_grant_user)
                if tags:
                    log.info("Tagging bucket {}".format(name))
                    _aws_do(b.set_tags, btags)
                return b
            except Exception as e:
                if retries == 0:
                    log.debug(e)
                    raise vFXTServiceFailure("Failed to create bucket {}: {}".format(name, e))
                retries -= 1

    def authorize_bucket(self, cluster, name, write_only=False, retries=ServiceBase.CLOUD_API_RETRIES, xmlrpc=None):
        '''Perform any backend work for the bucket, and register a credential
        for it to the cluster

            Arguments:
                cluster (Cluster): cluster object
                name (str): bucket name
                write_only (bool): this bucket is for write only (default False)
                retries (int): number of attempts to make
                xmlrpc (xmlrpcClt, optional): xmlrpc client

            Raises: vFXTServiceFailure
        '''
        xmlrpc = cluster.xmlrpc() if xmlrpc is None else xmlrpc
        existing_creds = cluster._xmlrpc_do(xmlrpc.corefiler.listCredentials, _xmlrpc_do_retries=retries)

        iam         = self.connection(connection_type='iam')
        iamrole     = cluster.iamrole
        policy_name = 'policy_{}'.format(iamrole)

        try:
            response = _aws_do(iam.list_role_policies, iamrole)
            policies = response['list_role_policies_response']['list_role_policies_result']['policy_names']
            # if this role has only one policy, use it
            if len(policies) == 1:
                policy_name = policies[0]
            elif policy_name not in policies:
                raise Exception("Unable to determine which policy to use")
        except Exception as e:
            raise vFXTConfigurationException("Could not find role policy for {}: {}".format(iamrole, e))

        response = _aws_do(iam.get_role_policy, iamrole, policy_name)
        if not response:
            raise vFXTServiceFailure("Failed to find existing policy")
        policy = json.loads(urllib2.unquote(response['get_role_policy_response']['get_role_policy_result']['policy_document']))

        bucket_policy = {
            'Action': self.IAM_BUCKET_POLICY,
            'Resource': ['arn:{}:s3:::{}'.format(self.arn, name)],
            'Effect': 'Allow'
        }
        object_policy = {
            'Action': self.IAM_OBJECT_POLICY_WRITE_ONLY if write_only else self.IAM_OBJECT_POLICY,
            'Resource': ['arn:{}:s3:::{}/*'.format(self.arn, name)],
            'Effect': 'Allow'
        }
        policy['Statement'].append(bucket_policy)
        policy['Statement'].append(object_policy)

        _aws_do(iam.put_role_policy, iamrole, policy_name, json.dumps(policy))

        # we cant reuse the existing default creds
        if self.s3_access_key != self.access_key:
            cred_name = 's3-{}'.format(cluster.name)

            # if it exists, use it
            if cred_name in [c['name'] for c in existing_creds]:
                return cred_name

            log.debug("Creating credential {}".format(cred_name))
            cred_body = {
                'accessKey': self.s3_access_key,
                'privateKey': self.s3_secret_access_key,
            }
            r = cluster._xmlrpc_do(xmlrpc.corefiler.createCredential, cred_name, self.COREFILER_CRED_TYPE, cred_body, _xmlrpc_do_retries=retries)
            if r != 'success':
                raise vFXTConfigurationException("Could not create credential {}: {}".format(cred_name, r))
            return cred_name

        # XXX otherwise assume first credential (internalName = cloudCredential1)
        if not existing_creds:
            raise vFXTConfigurationException("Could not find a credential to use")
        return existing_creds[0]['name']


    def delete_bucket(self, name):
        '''Delete a bucket

            Arguments:
                name (str): bucket name

            Raises: vFXTServiceFailure
        '''
        s3 = self.connection(connection_type='s3')

        try:
            b = _aws_do(s3.get_bucket, name)
            _aws_do(b.delete)
        except Exception as e:
            raise vFXTServiceFailure("Failed to delete bucket {}: {}".format(name, e))

    def create_instance(self, machine_type, name, boot_disk_image, other_disks=None, tags=None, **options):
        '''Create and return an AWS instance

            Arguments:
                machine_type (str): AWS machine type
                name (str): name of the instance (placed in tag)
                boot_disk_image (str): AMI ID name
                other_disks (boto.ec2.blockdevicemapping.BlockDeviceMapping): custom disk layout
                tags (dict): tags to apply to instance (Name tag auto filled)
                user_data (dict, optional): user_data to pass to the instance (for cluster_cfg, etc)
                placement_group (str, optional): placement group to launch instances in
                subnet (str, optional): subnet to place the instance in
                private_ip_address (str, optional): primary private IP address
                role_name (str, optional): role/profile name
                ebs_optimized (bool, optional): instance type specific
                key_name (str, optional): ssh key-pair name
                security_group_ids (str, optional):  space delimited list of security groups
                disableSourceDestCheck (bool, optional): disables instance sourceDestCheck
                root_size (int, optional): root disk size in GB
                root_dev_name (string, optional): root disk device name (defaults to AMI default)
                wait_for_success (int, optional): wait time for the instance to report success (default WAIT_FOR_SUCCESS)
                auto_public_address (bool, optional): auto assign a public address (defaults to False)

            Raises: vFXTConfigurationException, vFXTServiceFailure
        '''
        if not self.valid_instancename(name):
            raise vFXTConfigurationException("{} is not a valid instance name".format(name))
        machine_defs = self.MACHINE_DEFAULTS[machine_type]
        conn         = self.connection()

        # setup disks
        bdm = other_disks
        if not bdm:
            bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        root_opts = {}
        if options.get('root_size'):
            root_opts['size'] = options.get('root_size')
        root = boto.ec2.blockdevicemapping.BlockDeviceType(volume_type='gp2',
                    delete_on_termination=True, **root_opts)
        ami  = _aws_do(conn.get_image, boot_disk_image)
        if not ami:
            raise vFXTConfigurationException("{} is not a valid AMI".format(boot_disk_image))
        root_dev_name = options.get('root_dev_name', ami.root_device_name)
        bdm[root_dev_name] = root
        # fill in with blank disks if necessary
        base = ord('b')
        for idx in xrange(4):
            dev_name = "/dev/sd{:c}".format(base + idx)
            if dev_name not in bdm:
                dev      = boto.ec2.blockdevicemapping.BlockDeviceType(no_device=True)
                bdm[dev_name] = dev

        # general instance settings
        user_data       = options.get('user_data', '')
        placement_group = options.get('placement_group', None)
        subnet_id       = options.get('subnet') or self.subnets[0]
        ip_address      = options.get('private_ip_address', None)
        role_name       = options.get('role_name', None)
        subnet          = self._get_subnet(subnet_id)
        az              = subnet.availability_zone
        ebs_optimized   = options.get('ebs_optimized', machine_defs['ebsoptimized'])
        key_name        = options.get('key_name', None)
        security_groups = options.get('security_group_ids', None)
        tenancy         = 'dedicated' if options.get('dedicated_tenancy') else None

        if security_groups and isinstance(security_groups, basestring):
            security_groups = [_ for _ in security_groups.split(' ')]

        interfaces = None
        if options.get('auto_public_address', False):
            interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(subnet_id=subnet_id, groups=security_groups, associate_public_ip_address=True)
            interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(interface)
            subnet_id = None # cannot specify this at instance level if doing it at interface level
            ip_address = None # Network interfaces and an instance-level private IP address may not be specified on the same request
            security_groups = None # Network interfaces and an instance-level security groups may not be specified on the same request

        create_options = {
            'instance_type': machine_type,
            'subnet_id': subnet_id,
            'placement_group': placement_group,
            'block_device_map': bdm,
            'user_data': user_data,
            'placement': az,
            'private_ip_address': ip_address,
            'ebs_optimized': ebs_optimized,
            'instance_profile_name': role_name,
            'key_name': key_name,
            'security_group_ids': security_groups,
            'network_interfaces': interfaces,
            'tenancy': tenancy,
        }
        log.debug("create_instance request body: {}, {}".format(boot_disk_image, create_options))

        # http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#launch-instance-with-role-cli
        # "After you create an IAM role, it may take several seconds for the permissions to propagate."
        # XXX we might not have the instance profile or the roles may not yet be populated
        iam_propagation_msgs = ['has no associated IAM Roles', 'Invalid IAM Instance Profile']
        retries = self.CREATE_INSTANCE_IAM_PROPAGATION_RETRIES
        while retries > 0:
            try:
                r = _aws_do_non_idempotent(conn.run_instances, boot_disk_image, **create_options)
                break
            except Exception as e:
                log.debug('Run instances failed: {}'.format(e))
                retries -= 1

                if retries > 0 and [_ for _ in iam_propagation_msgs if _ in e.message]:
                    log.debug("Retrying awaiting IAM propagation: {}".format(e))
                    time.sleep(self.POLLTIME)
                    continue

                log.debug("Create instance failed: {}".format(e))
                raise vFXTServiceFailure(e)

        instance = r.instances[0]

        # use wait_for_status of pending prior to tagging
        try:
            self.wait_for_status(instance, self.PENDING_STATUS)
        except Exception as e:
            log.debug(e)
            # sometimes we pass the pending status quickly and go right to running
            if instance.update() not in [self.PENDING_STATUS, self.ON_STATUS]:
                raise

        # tags
        tags = tags or {}
        tags['Name'] = name
        try:
            log.debug("Tagging instance {} with {}".format(instance.id, tags))
            _aws_do(conn.create_tags, instance.id, tags)

            # tag volumes
            instance = self.refresh(instance) # refresh to get latest block device mapping
            for vname, vdev in instance.block_device_mapping.iteritems():
                vol_tags = tags.copy()
                vol_tags['Name'] = "{}-{}".format(tags['Name'], vname[vname.rfind("/") + 1:])
                log.debug("Tagging volume {} with {}".format(vdev.volume_id, vol_tags))
                _aws_do(conn.create_tags, vdev.volume_id, vol_tags)
        except Exception as e:
            log.exception(e)
            _aws_do(instance.terminate)
            self.wait_for_status(instance, self.DESTROY_STATUS, 600)
            raise vFXTServiceFailure(e)

        if options.get('disableSourceDestCheck'):
            dsd_retries = ServiceBase.CLOUD_API_RETRIES
            while True:
                try:
                    _aws_do(conn.modify_instance_attribute, instance.id, attribute='sourceDestCheck', value=False)
                    break
                except Exception as e:
                    time.sleep(self.POLLTIME)
                    dsd_retries -= 1
                    if dsd_retries == 0:
                        raise

        wait_for_success = options.get('wait_for_success') or self.WAIT_FOR_SUCCESS
        self.wait_for_status(instance, self.ON_STATUS, wait_for_success)
        return instance

    def create_node(self, node_name, cfg, node_opts, instance_options):
        '''Create a cluster node

            This is a frontend for create_instance that handles vFXT node specifics

            Arguments:
                node_name (str): name of the node
                cfg (str): configuration string to pass to the node
                node_opts (dict): node creation options
                instance_options (dict): options passed to create_instance

                node_opts include:
                    data_disk_size: size of data disks
                    data_disk_type: type of data disks
                    data_disk_count: number of data disks
                    data_disk_iops (optional)
                    tags (dict)
                    machine_type
                    role: (iam role dict from AWS)
                    root_image: AMI id
                    disk_encryption (bool): defaults to True

        '''
        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        tags = {}
        tags.update(node_opts.get('tags', {}))
        tags['Name'] = node_name

        if node_opts['data_disk_type'] == 'ephemeral':
            if 'ebs_optimized' in instance_options:
                instance_options['ebs_optimized'] = False
            base = ord('b')
            for idx in xrange(4): # ignore data_disk_size for ephemeral
                name     = 'ephemeral{}'.format(idx)
                dev_name = "/dev/sd{:c}".format(base + idx)
                dev      = boto.ec2.blockdevicemapping.BlockDeviceType(ephemeral_name=name)
                bdm[dev_name] = dev
        else:
            base = ord('f')
            for idx in xrange(node_opts['data_disk_count']):
                opts = {
                    'size':                  node_opts['data_disk_size'],
                    'volume_type':           node_opts['data_disk_type'],
                    'delete_on_termination': True,
                    'iops':                  node_opts['data_disk_iops'],
                    'encrypted':             node_opts.get('disk_encryption', True)
                }
                dev       = boto.ec2.blockdevicemapping.BlockDeviceType(**opts)
                name      = "/dev/sd{:c}".format(base + idx)
                bdm[name] = dev

        log.info("Creating node {}".format(node_name))
        n = self.create_instance(machine_type=node_opts['machine_type'],
                    name=node_name,
                    boot_disk_image=node_opts['root_image'],
                    other_disks=bdm,
                    tags=tags,
                    user_data=cfg,
                    role_name=node_opts['role']['role_name'],
                    **instance_options
        )
        log.info("Created {}/{} ({})".format(node_name, n.id, n.private_ip_address))
        return n

    def create_cluster(self, cluster, **options):
        '''Create a vFXT cluster (calls create_node for each node)
            Typically called via vFXT.Cluster.create()

            Arguments:
                cluster (vFXT.cluster.Cluster): cluster object
                size (int, optional): size of cluster (node count)
                subnet (str or []): one or more subnets
                root_image (str, optional): AMI id (or machine type default)
                data_disk_size (int, optional): size of data disk (or machine type default)
                data_disk_count (int, optional): number of data disks (or machine type default)
                data_disk_type (str, optional): type of data disks (or machine type default)
                data_disk_iops (int, optional): IOPs value for EBS optimized disks (or machine type default, 250)
                tags (dict, optional): tags for instance (Name autofilled)
                iamrole (str, optional): iam role (otherwise one is created)
                config_expiration (int, optional): expiration time for cluster join configuration
                skip_cleanup (bool, optional): do not clean up on failure
                key_name (str, optional): ssh key-pair name
                management_address (str, optional): management address for the cluster
                address_range_start (str, optional): The first of a custom range of addresses to use for the cluster
                address_range_end (str, optional): The last of a custom range of addresses to use for the cluster
                address_range_netmask (str, optional): cluster address range netmask

                Additional arguments are passed through to create_node()

            Raises: vFXTConfigurationException, vFXTCreateFailure

        '''
        if not all([cluster.mgmt_ip, cluster.mgmt_netmask, cluster.cluster_ip_start, cluster.cluster_ip_end]):
            raise vFXTConfigurationException("Cluster networking configuration is incomplete")

        machine_type = cluster.machine_type

        if machine_type not in self.MACHINE_TYPES:
            raise vFXTConfigurationException("{} is not a valid instance type".format(machine_type))

        machine_defs = self.MACHINE_DEFAULTS[machine_type]
        cluster_size = int(options.get('size', machine_defs['node_count']))

        # networking
        subnets = options.get('subnet') or self.subnets
        subnets = [subnets] if isinstance(subnets, basestring) else subnets
        cluster.subnets = [subnets[0]] # first node subnet

        # check subnet objects for mapPublicIpOnLaunch
        for subnet_id in subnets:
            if self._get_subnet(subnet_id).mapPublicIpOnLaunch == 'true':
                log.warn("Subnet {} has mapPublicIpOnLaunch enabled".format(subnet_id))

        # check that our subnets share a route table
        route_tables = set()
        vpcconn = self.connection('vpc')
        for subnet_id in subnets:
            subnet_route_tables = _aws_do(vpcconn.get_all_route_tables, filters={'association.subnet-id': subnet_id})
            if not subnet_route_tables:
                route_tables.add('main') # main is the default route table
            else:
                route_tables.update([_.id for _ in subnet_route_tables if _ and _.id])
        if len(route_tables) > 1:
            raise vFXTConfigurationException("All subnets must share the same route table")

        # if we are going to span multiple subnets we can not assign the private ip address
        instance_addresses = cluster.instance_addresses
        if not instance_addresses or len(subnets) > 1:
            instance_addresses = [None] * cluster_size

        # disks
        root_image      = options.get('root_image') or self._get_default_image()
        data_disk_size  = options.get('data_disk_size') or machine_defs['data_disk_size']
        data_disk_count = options.get('data_disk_count') or machine_defs['data_disk_count']
        data_disk_type  = options.get('data_disk_type') or machine_defs['data_disk_type']
        data_disk_iops  = options.get('data_disk_iops') or machine_defs.get('data_disk_iops', 250)
        if data_disk_type != 'io1':
            data_disk_iops = None
        disk_encryption = options.pop('disk_encryption', True)

        # tags
        tags = options.pop('tags', {})

        # role
        iamrole = options.get('iamrole', None)
        role    = None
        if iamrole: # verify
            role = self._get_iamrole(iamrole)
        else:
            role = self._create_iamrole('avere_cluster_role_{}_{}'.format(int(time.time()), cluster.name))
        cluster.iamrole = role['role_name']

        log.info('Creating cluster configuration')
        # config
        cfg     = cluster.cluster_config(expiration=options.get('config_expiration', None))
        cfg     +=  '''\n[EC2 admin credential]''' \
                    '''\nname={0}''' \
                    '''\nrole={0}''' \
                    .format(role['role_name'])
        log.debug("Generated cluster config: {}".format(cfg.replace(cluster.admin_password, '[redacted]')))

        # for point to point addressing we need to disable Source/Dest checks
        if cluster.mgmt_netmask == '255.255.255.255':
            options['disableSourceDestCheck'] = True

        try:
            name = '{}-{:02}'.format(cluster.name, 1)
            opts = {'data_disk_type': data_disk_type, 'data_disk_count': data_disk_count,
                    'tags': tags.copy(), 'data_disk_size': data_disk_size,
                    'data_disk_iops': data_disk_iops, 'machine_type': machine_type,
                    'root_image': root_image, 'role': role, 'disk_encryption': disk_encryption}
            inst_opts = options.copy()
            inst_opts['subnet'] = subnets[0] # first node subnet
            inst_opts['private_ip_address'] = instance_addresses.pop(0)
            n    = self.create_node(name, cfg, node_opts=opts, instance_options=inst_opts)
            cluster.nodes.append(ServiceInstance(service=self, instance=n))

            # post first node setup, prior to creating the rest of the cluster
            threads = []
            if not options.get('skip_configuration'):
                t = threading.Thread(target=cluster.first_node_configuration)
                t.setDaemon(True)
                t.start()
                threads.append(t)
            options.update(opts)
            options['private_ip_addresses'] = instance_addresses
            options['subnet'] = subnets if len(subnets) == 1 else subnets[1:]
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
        try:
            if hasattr(cluster, 'iamrole'):
                iamrole = cluster.iamrole
                # Note we don't want to just delete a role, unless we created it
                if iamrole.startswith('avere_cluster_role_'):
                    self._delete_iamrole(iamrole)
        except Exception as e:
            log.debug("Cleanup failed: {}".format(e))

    def _add_cluster_nodes_setup(self, cluster, count, **options):
        pass

    def add_cluster_nodes(self, cluster, count, **options):
        '''Add nodes to the cluster (delegates to create_node())

            Arguments:
                cluster (vFXT.cluster.Cluster): cluster object
                count (int): number of nodes to add
                skip_cleanup (bool, optional): do not clean up on failure
                instance_addresses ([], optional): list of instance addresses
                **options: passed to create_node()

            Raises: exceptions from create_node()
        '''
        if count < 1: return

        subnets = options.get('subnet') or cluster.subnets if hasattr(cluster, 'subnets') else self.subnets
        subnets = [subnets] if isinstance(subnets, basestring) else subnets
        # make sure to use unused subnets first, but account for our cluster subnets
        subnets.extend([s for s in cluster.subnets if s not in subnets])
        cycle_subnets = cycle(subnets)

        # if we are preallocating our instance_addresses
        instance_addresses = options.pop('instance_addresses', [None] * count)
        if len(instance_addresses) != count:
            raise vFXTConfigurationException("Not enough instance addresses were provided")
        # but only for non-xaz setups
        if len(subnets) > 1:
            log.debug("Resetting instance addresses to be provided via the backend service")
            instance_addresses = [None] * count

        instance        = cluster.nodes[0].instance
        role            = self._get_iamrole(cluster.iamrole)
        security_groups = [_.id for _ in instance.groups]

        if not options.get('security_group_ids'):
            options['security_group_ids'] = security_groups
        # overrides
        opts = {'tags': instance.tags, 'data_disk_iops': None, 'machine_type': cluster.machine_type, 'root_image': instance.image_id, 'role': role}
        overrides = ['tags', 'machine_type', 'root_image', 'data_disk_size', 'data_disk_type', 'data_disk_count', 'disk_encryption']
        for o in overrides:
            if o in options:
                opts[o] = options.pop(o)

        if not all([_ in opts for _ in ['data_disk_count', 'data_disk_type', 'data_disk_size']]):
            conn = self.connection()
            bdm             = instance.block_device_mapping
            non_root_vols   = [_aws_do(conn.get_all_volumes, bdm[vol].volume_id)[0] for vol in bdm if vol != instance.root_device_name]
            if non_root_vols:
                opts['data_disk_count'] = len(non_root_vols)
                opts['data_disk_type']  = non_root_vols[0].type
                opts['data_disk_size']  = non_root_vols[0].size
            else: # ephemeral
                opts['data_disk_count'] = 4
                opts['data_disk_type']  = 'ephemeral'
                opts['data_disk_size']  = None

        # Requires cluster be online
        # XXX assume our node name always ends in the node number
        max_node_num = max([int(i.name().split('-')[-1]) for i in cluster.nodes])

        joincfg = cluster.cluster_config(joining=True, expiration=options.get('config_expiration', None))

        nodeq   = Queue.Queue()
        failq   = Queue.Queue()
        threads = []
        def cb(nodenum, inst_opts, nodeq, failq):
            '''callback'''
            try:
                name = '{}-{:02}'.format(cluster.name, nodenum)
                n = self.create_node(name, joincfg, node_opts=opts, instance_options=inst_opts)
                nodeq.put(n)
            except Exception as e:
                if not log.isEnabledFor(logging.DEBUG):
                    log.exception(e)
                failq.put(e)

        for node_num in xrange(max_node_num, max_node_num + count):
            next_node_num = node_num + 1
            inst_opts = options.copy()
            inst_opts['subnet'] = next(cycle_subnets)
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
        conn       = self.connection()
        xmlrpc     = cluster.xmlrpc()

        # make sure mgmt_ip is set to the valid address (in case we used
        # a node address to get in)
        cluster.mgmt_ip = xmlrpc.cluster.get()['mgmtIP']['IP']

        node_ips = set([n['primaryClusterIP']['IP']
                        for name in xmlrpc.node.list()
                        for n in [xmlrpc.node.get(name)[name]]
                        if 'primaryClusterIP' in n])

        expr = {"private_ip_address": list(node_ips)}
        instances = [i for r in _aws_do(conn.get_all_reservations, filters=expr) for i in r.instances]

        # we should always find the private addresses in the cluster IP list
        #if not instances or len(instances) != len(node_ips): # maybe point 2 point
        #    vpc = self.connection(connection_type='vpc')
        #    route_instances = [self.get_instance(r.instance_id)
        #                          for rt in vpc.get_all_route_tables()
        #                          for r in rt.routes
        #                          if r.instance_id
        #                            and r.destination_cidr_block.endswith('/32')
        #                            and r.destination_cidr_block.split('/')[0] in node_ips ]
        #    instances = route_instances

        if instances:
            cluster.nodes = []
            for i in instances:
                cluster.nodes.append(ServiceInstance(service=self, instance=i))

            cluster.subnets      = list(set([i.subnet_id for i in instances]))
            # XXX assume all instances have the same settings
            cluster.iamrole      = instances[0].instance_profile['arn'].split('/')[-1]
            cluster.vpc_id       = instances[0].vpc_id
            cluster.machine_type = instances[0].instance_type
            cluster.ephemeral    = True if len(instances[0].block_device_mapping) == 1 else False
            cluster.name         = self.CLUSTER_NODE_NAME_RE.search(cluster.nodes[0].name()).groups()[0]

    def can_shelve(self, instance):
        ''' Some instance configurations cannot be shelved. Check if this is one.

            Arguments:
                instance: backend instance
        '''
        return True

    def shelve(self, instance):
        ''' shelve the instance; shut it down, detach and delete
            all non-root block devices

            Arguments:
                instance: backend instance
            Raises: vFXTServiceFailure
        '''
        conn     = self.connection()

        if not self.can_shelve(instance):
            raise vFXTConfigurationException("{} configuration prevents shelving".format(self.name(instance)))
        if self.is_shelved(instance):
            raise vFXTConfigurationException("{} is already shelved".format(self.name(instance)))

        if instance.state == self.DESTROY_STATUS:
            return

        bdm = instance.block_device_mapping
        if not bdm:
            raise vFXTServiceFailure("Failed to get block device mapping for {}".format(instance.id))

        non_root_vols = [_aws_do(conn.get_all_volumes, bdm[vol].volume_id)[0]
                            for vol in bdm if vol != instance.root_device_name]

        if not non_root_vols:
            log.info("No non-root volumes for instance {}, already shelved?".format(instance.id))
            return

        log.debug("Found non-root volumes: {}".format(non_root_vols))

        if self.is_on(instance):
            self.stop(instance)

        # XXX assume all volume attributes are uniform
        tag = {
            'shelved': "{}|{}|{}".format(
                len(non_root_vols),
                non_root_vols[0].size,
                non_root_vols[0].type)
        }

        errors          = ShelveErrors()
        detach_failed   = []
        for nrv in non_root_vols:
            log.info("{}|{}: detaching and deleting {}".format(
                instance.tags['Name'],
                instance.id,
                nrv.id))
            try:
                _aws_do(conn.detach_volume, nrv.id, instance.id)
                self.wait_for_status(nrv, "available", retries=self.WAIT_FOR_SUCCESS)
                _aws_do(nrv.delete)
            except Exception:
                detach_failed.append(nrv.id)

        if detach_failed:
            errors['notdetached'] = ",".join(detach_failed)

        if errors:
            # XXX hopefully we don't exceed 255 characters
            tag['shelved'] += '|{}'.format(errors)

        _aws_do(conn.create_tags, instance.id, tag)
        log.debug("Creating instance tags: {}".format(tag))

    def unshelve(self, instance, count_override=None, size_override=None, type_override=None, **options):
        ''' bring our instance back to life.  This requires a tag called
            shelved that contains the number of disks and their size/type

            Arguments:
                instance: backend instance
                count_override (int, optional): number of data disks
                size_override (int, optional): size of data disks
                type_override (str, optional): type of data disks

            AWS specific arguments:
                encrypted (bool, True): use EBS encryption
                kms_key_id (str, None): use a specific KMS key ID for volumes created

            Raises: vFXTServiceFailure
        '''
        conn        = self.connection()

        # assume we've previously killed the data disks and set a tag
        if "shelved" not in instance.tags:
            log.info( "{} does not have shelved tag, skipping".format(instance.id))
            return
        # XXX assume instance is already stopped
        if instance.state != self.OFF_STATUS:
            log.info("{} is not stopped, skipping".format(instance.id))
            return

        try:
            attrs = instance.tags['shelved'].split("|")
            vol_count, vol_size, vol_type = attrs[0:3]
            log.debug("Split {}, {}, {} from {}".format(
                vol_count, vol_size, vol_type, instance.tags['shelved']))
        except Exception:
            log.error("{} does not have data in the shelved tag".format(instance.id))
            return

        # verify our non-ephemeral disks (/dev/sd[f-p]) labels are available
        if '/dev/sdf' in instance.block_device_mapping:
            log.info("{} appears to already have data disks, skipping".format(instance.id))
            return

        if count_override:
            vol_count = count_override
        if size_override:
            vol_size = size_override
        if type_override:
            vol_type = type_override

        volumes_created = []
        try:
            # -- we have to support ephemeral disks
            # create an ephemeral instance (or find one) to examine
            # http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html
            drive_id_base = ord('f')
            for i in xrange(int(vol_count)):
                drive_name = drive_id_base + i
                dev_name   = "/dev/sd{:c}".format(drive_name)

                log.debug("{}|{}: creating {} volume {} of type {} in {}".format(
                    instance.tags['Name'],
                    instance.id,
                    vol_size,
                    dev_name,
                    vol_type,
                    instance.placement))
                vol = _aws_do_non_idempotent(conn.create_volume, vol_size,
                                         instance.placement,
                                         encrypted=options.get('encrypted', True),
                                         kms_key_id=options.get('kms_key_id', None),
                                         volume_type=vol_type)
                volumes_created.append(vol)

                tags = {}
                tags['Name'] = "{}-sd{:c}".format(instance.tags['Name'], drive_name)

                # get Owner, Department if available
                if 'Owner' in instance.tags:
                    tags['Owner']       = instance.tags['Owner']
                if 'Department' in instance.tags:
                    tags['Department']  = instance.tags['Department']

                log.debug("Creating volume tags: {}".format(tags))
                _aws_do(conn.create_tags, vol.id, tags)

                self.wait_for_status(vol, 'available')
                _aws_do(vol.attach, instance.id, dev_name)
                self.wait_for_status(vol, 'in-use')
                _aws_do(instance.modify_attribute, 'blockDeviceMapping', [ "{}=1".format(dev_name)])

        except boto.exception.BotoServerError as e:
            log.debug(e)
            log.error("Error while creating volumes, undoing what we did")
            for vol in volumes_created:
                if vol.attach_data and vol.attach_data.instance_id:
                    log.debug("Detaching volume {} from instance {}".format(vol.id, vol.attach_data.instance_id))
                    _aws_do(conn.detach_volume, vol.id, vol.attach_data.instance_id)
                    self.wait_for_status(vol, "available")
                log.debug("Deleting volume {}".format(vol.id))
                vol.delete()
            raise vFXTServiceFailure(e)

        _aws_do(conn.delete_tags, instance.id, ['shelved'])
        _aws_do(instance.start)

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
        netmask    = None
        addr_range = addr_range or self.private_range
        if not addr_range:
            if len(self.subnets) == 1: # fall back to a subnet if only one
                addr_range = self._get_subnet(self.subnets[0]).cidr_block
                log.debug("Using subnet {} range of {}".format(self.subnets[0], addr_range))
            else: # lots of subnets, determine a private range outside vpc XXX review
                # this requires permission to view vpc
                vpc_cidr   = Cidr(self._subnet_to_vpc().cidr_block)
                addr_range = '{}/{}'.format(Cidr.to_address(vpc_cidr.end() + 1), vpc_cidr.bits)
                netmask = '255.255.255.255'
                log.debug("Using range {} outside of VPC range of {}".format(addr_range, vpc_cidr))
        else:
            netmask = '255.255.255.255'
            log.debug("Using specified address range {}".format(addr_range))

        used = self.in_use_addresses(addr_range)
        if in_use:
            used.extend(in_use)
            used = list(set(used))

        try:
            addr_cidr  = Cidr(addr_range)
            avail = addr_cidr.available(count, contiguous, used)
            if not netmask:
                netmask = addr_cidr.netmask
            return (avail, netmask)
        except Exception as e:
            raise vFXTConfigurationException("Check that the subnet or specified address range has enough free addresses: {}".format(e))

    def get_dns_servers(self, subnet_id=None):
        '''Get DNS server addresses

            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)
            Returns:
                [str]: list of DNS server addresses
        '''
        subnet_id = subnet_id or self.subnets[0]
        # self.DNS_SERVERS is empty, we look to DHCP options
        try:
            opts = self._get_dhcp_options(subnet_id)
            dns  = opts['domain-name-servers']
            if dns and dns[0] == 'AmazonProvidedDNS':
                vpc_cidr = self._subnet_to_vpc(subnet_id).cidr_block
                default_addr = Cidr.to_address(Cidr(vpc_cidr).start() + 2)
                dns = [default_addr]
            return dns
        except Exception as e:
            raise vFXTServiceFailure("Failed to determine DNS configuration: {}".format(e))

    def get_ntp_servers(self, subnet_id=None):
        '''Get NTP server addresses
            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)

            Returns:
                [str]: list of NTP server addresses
        '''
        subnet_id = subnet_id or self.subnets[0]
        try:
            opts = self._get_dhcp_options(subnet_id)
            return opts.get('ntp-servers') or self.NTP_SERVERS
        except Exception:
            return self.NTP_SERVERS

    def get_default_router(self, subnet_id=None):
        '''Get default route address

            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)
            Returns:
                str: address of default router
        '''
        subnet_id = subnet_id or self.subnets[0]
        subnet    = self._get_subnet(subnet_id)
        c         = Cidr(subnet.cidr_block)
        return c.to_address(c.start() | 1)

    def export(self):
        '''Export the service object in an easy to serialize format
            Returns:
                {}: serializable dictionary
        '''
        export = {
            'region': self.region,
            'access_key': self.access_key,
            'secret_access_key': self.secret_access_key,
        }
        if self.s3_access_key != self.access_key:
            export['s3_access_key'] = self.s3_access_key
            export['s3_secret_access_key'] = self.s3_secret_access_key
            if self.s3_profile_name:
                export['s3_profile_name'] = self.s3_profile_name
        if self.subnets:
            export['subnet'] = self.subnets
        if self.profile_name:
            export['profile_name'] = self.profile_name
        if self.security_token:
            export['security_token'] = self.security_token
        if self.private_range:
            export['private_range'] = self.private_range
        if self.proxy_uri:
            export['proxy_uri'] = self.proxy_uri
        if self.iam_host:
            export['iam_host'] = self.iam_host
        if self.arn:
            export['arn'] = self.arn
        if self.iam_role_principal_service:
            export['iam_role_principal_service'] = self.iam_role_principal_service

        return export


    # AWS specific

    def _subnet_to_vpc(self, subnet_id=None):
        '''Lookup VPC by subnet

            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)
            Returns:
                obj: VPC object
        '''
        subnet_id = subnet_id or self.subnets[0]
        subnet    = self._get_subnet(subnet_id)
        vpc       = _aws_do(subnet.connection.get_all_vpcs, vpc_ids=[subnet.vpc_id])[0]
        return vpc

    def _get_dhcp_options(self, subnet_id=None):
        '''Get DHCP options

            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)
            Returns:
                {}: dict of DHCP options
        '''
        subnet_id = subnet_id or self.subnets[0]
        vpc       = self._subnet_to_vpc(subnet_id)
        conn      = vpc.connection
        optid     = vpc.dhcp_options_id
        r         = _aws_do(conn.get_all_dhcp_options, dhcp_options_ids=[optid])
        return r[0].options

    def _get_subnet(self, subnet_id=None):
        '''Get subnet object by ID

            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)
            Returns:
                obj: subnet object
        '''
        subnet_id = subnet_id or self.subnets[0]
        vpc = self.connection(connection_type='vpc')
        subnet = _aws_do(vpc.get_all_subnets, subnet_ids=[subnet_id])[0]
        return subnet

    def in_use_addresses(self, cidr_block, category='all'):
        '''Return a list of in use addresses within the specified cidr

            Arguments:
                cidr_block (str)
                category (str): all, interfaces, routes
        '''
        vpcconn = self.connection(connection_type='vpc')
        c       = Cidr(cidr_block)
        used    = set()

        # XXX whole lotta expensiveness
        if category in ['all', 'routes']:
            try:
                addrs = [r.destination_cidr_block.split('/')[0]
                        for rt in _aws_do(vpcconn.get_all_route_tables)
                        for r in rt.routes
                        if r.instance_id and
                        c.contains(r.destination_cidr_block.split('/')[0])]
                used.update(addrs)
            except Exception as e:
                log.error('Failed to determine in use addresses by routes: {}'.format(e))
                raise vFXTServiceFailure('Failed to determine in use addresses by routes: {}'.format(e))

        # search all network interface private ip addresses that fail within the specified block
        # XXX whole lotta expensiveness
        if category in ['all', 'interfaces']:
            try:
                conn = self.connection()
                addrs = [addr.private_ip_address
                            for iface in _aws_do(conn.get_all_network_interfaces)
                            for addr in iface.private_ip_addresses
                            if c.contains(addr.private_ip_address)]
                used.update(addrs)
            except Exception as e:
                log.error('Failed to determine in use addresses by instances: {}'.format(e))
                raise vFXTServiceFailure('Failed to determine in use addresses by instances: {}'.format(e))

        return list(used)

    def _get_iamrole(self, name, retries=ServiceBase.CLOUD_API_RETRIES):
        '''Retrieve the IAM role object

            Arguments:
                name (str): IAM role name
                retries (int, optional): number of retries
            Returns:
                obj: IAM role object
        '''
        iam = self.connection(connection_type='iam')

        while True:
            try:
                role = _aws_do(iam.get_role, name)
                log.debug("Fetched role {}".format(name))
                return role['get_role_response']['get_role_result']['role']
            except Exception as e:
                if retries == 0:
                    raise vFXTServiceTimeout(e)
                retries -= 1

    def _create_iamrole(self, name):
        '''Create an IAM role

            Arguments:
                name (str): name of the IAM role to create
        '''
        iam = self.connection(connection_type='iam')

        # role name must be <= 64 chars long
        if len(name) > 64:
            log.warn("Truncating role name from {} to {}".format(name, name[0:63]))
            name = name[0:63]

        policy = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': self.IAM_POLICY,
                    'Resource': '*',
                    'Effect': 'Allow'
                },
            ]
        }

        role_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": { "Service": self.iam_role_principal_service},
                "Action": "sts:AssumeRole"
            }]
        }

        log.info("Creating instance profile {}".format(name))
        profile     = _aws_do_non_idempotent(iam.create_instance_profile, name) #pylint: disable=unused-variable
        log.debug("Creating instance profile policy {}: {}".format(name, role_policy))
        role        = _aws_do_non_idempotent(iam.create_role, name, json.dumps(role_policy))
        policy_name = 'policy_{}'.format(name)
        log.debug("Adding role policy {}: {}".format(policy_name, policy))
        _aws_do(iam.put_role_policy, name, policy_name, json.dumps(policy))
        log.info("Adding role {} to instance profile {}".format(name, name))
        _aws_do(iam.add_role_to_instance_profile, name, name)
        time.sleep(5) # XXX Wow, sync time between IAM service and EC2
        return role['create_role_response']['create_role_result']['role']

    def _delete_iamrole(self, name):
        '''Delete an IAM role and cleanup role/policies applied to it

            Arguments:
                name (str): name of the IAM role to delete
        '''
        iam = self.connection(connection_type='iam')

        log.info("Removing role {} from instance profile".format(name))
        _aws_do(iam.remove_role_from_instance_profile, name, name)
        log.info("Removing instance profile {}".format(name))
        _aws_do(iam.delete_instance_profile, name)

        resp = _aws_do(iam.list_role_policies, name)
        role_policies = resp['list_role_policies_response']['list_role_policies_result']['policy_names']
        for role_policy in role_policies:
            log.info("Removing role {} policy".format(role_policy))
            _aws_do(iam.delete_role_policy, name, role_policy)

        log.info("Removing role {}".format(name))
        _aws_do(iam.delete_role, name)

    def add_instance_address(self, instance, address, **options):
        '''Add a new instance private address or route

            Arguments:
                instance: backend instance
                address (str): IP address
                allow_reassignment (bool, optional): defaults to True
                route_tables (list, optional): list of additional route table IDs to add the address to

            If the address is not contained within the instances default subnet, point to point
            routes are added.

            Raises: vFXTServiceFailure
        '''
        try:
            addr = Cidr('{}/32'.format(address)) # validates
            existing = self.instance_in_use_addresses(instance)
            if addr.address in existing:
                raise vFXTConfigurationException("Address {} is already associated with instance {}".format(addr.address, self.name(instance)))

            # if part of the subnet, add to private addresses
            subnet = self._get_subnet(instance.subnet_id)
            subnet_block = Cidr(subnet.cidr_block)
            if subnet_block.contains(addr.address):
                conn = self.connection()
                _aws_do_non_idempotent(conn.assign_private_ip_addresses, instance.interfaces[0].id,
                    private_ip_addresses=[addr.address],
                    allow_reassignment=options.get('allow_reassignment', True))
                log.debug("Added private address {}".format(addr.address))

            else: # otherwise we will need a route
                conn = self.connection(connection_type='vpc')
                route_tables = self._get_route_tables()
                route_tables.extend(options.get('route_tables', []))

                for rt_id in route_tables:
                    try:
                        _aws_do_non_idempotent(conn.create_route, rt_id, '{}/32'.format(addr.address), instance_id=instance.id)
                        log.debug("Added routed address {} to {}".format(addr.address, rt_id))
                        continue
                    except Exception as e:
                        if 'RouteAlreadyExists' not in str(e):
                            raise
                    _aws_do(conn.replace_route, rt_id, '{}/32'.format(addr.address), instance_id=instance.id)
                    log.debug("Replaced routed address {} in {}".format(addr.address, rt_id))

        except vFXTConfigurationException:
            raise
        except Exception as e:
            raise vFXTServiceFailure("Failed to create new address for instance {}.  Check the IAM policy for required permissions (including ec2:DescribeSubnets).  Error: {}".format(self.name(instance), e))

    def remove_instance_address(self, instance, address):
        '''Remove an instance private address or route

            Arguments:
                instance: backend instance
                address (str): IP address

            Raises: vFXTServiceFailure
        '''
        try:
            addr = Cidr('{}/32'.format(address)) # validates
            instance_addresses = self.instance_in_use_addresses(instance, 'instance')
            routed_addresses = self.instance_in_use_addresses(instance, 'routes')

            if addr.address in instance_addresses:
                conn = self.connection()
                _aws_do(conn.unassign_private_ip_addresses, instance.interfaces[0].id, [addr.address])
                log.debug("Removed private address {}".format(addr.address))
            elif addr.address in routed_addresses:
                conn = self.connection(connection_type='vpc')
                route_addr = '{}/32'.format(addr.address)
                route_tables = [rt.id
                    for rt in _aws_do(conn.get_all_route_tables)
                    for r in rt.routes
                    if r.destination_cidr_block == route_addr]
                for rt_id in route_tables:
                    log.debug("Removed routed address {} from route table {}".format(addr.address, rt_id))
                    _aws_do(conn.delete_route, rt_id, route_addr)
            else:
                raise vFXTServiceFailure("Address {} is not associated with instance {}".format(addr.address, self.name(instance)))
        except Exception as e:
            raise vFXTServiceFailure("Failed to remove address from instance {}: {}".format(self.name(instance), e))

    def instance_in_use_addresses(self, instance, category='all'):
        '''Get the in use addresses for the instance
            Arguments:
                instance (object)
                category (str): all (default), instance, routes

            To obtain the public instance address, use 'public' category.  This
            is not included with 'all'.
        '''
        addresses = set()
        if category in ['all', 'instance']:
            private_addrs = [addr.private_ip_address for iface in instance.interfaces for addr in iface.private_ip_addresses]
            addresses.update(set(private_addrs))

        if category in ['all', 'routes']:
            vpcconn     = self.connection(connection_type='vpc')
            route_addrs = [r.destination_cidr_block.split('/')[0]
                            for rt in _aws_do(vpcconn.get_all_route_tables)
                            for r in rt.routes
                            if r.instance_id and
                                r.instance_id == instance.id and
                                r.destination_cidr_block.endswith('/32')
                            ]
            addresses.update(set(route_addrs))

        # for special requests
        if category == 'public':
            if instance.ip_address:
                addresses.add(instance.ip_address)

        return list(addresses)

    def valid_instancename(self, name):
        '''Validate the instance name

            Returns: bool
        '''
        if not ServiceBase.valid_instancename(self, name):
            return False
        if name.startswith('aws:'):
            return False
        if self.INSTANCENAME_RE.match(name):
            return True
        return False

    def _get_route_tables(self, subnets=None):
        '''Returns a list of associated route tables with the
            subnets specified

            Arguments:
                subnets ([], optional): defaults to service subnets

            Returns list
        '''
        subnets = subnets if subnets else self.subnets
        subnets = [self._get_subnet(subnet_id) for subnet_id in subnets]
        subnet_ids = [_.id for _ in subnets]
        vpc_id = subnets[0].vpc_id
        vpcconn = self.connection(connection_type='vpc')
        try:
            return [a.route_table_id
                for rt in _aws_do(vpcconn.get_all_route_tables, filters={'vpc-id': vpc_id})
                for a in rt.associations
                if a.main or a.subnet_id in subnet_ids]
        except Exception as e:
            log.debug('Failed trying to lookup route tables: {}'.format(e))
        return []

    def _region_names(self):
        '''Get a list of region names
            Returns: list
        '''
        conn = self.connection()
        return [r.name for r in _aws_do(conn.get_all_regions)]

    def _s3_fetch(self, url, filename):
        '''Retrieve the object from S3, writing it to the passed in file location

            Arguments:
                url (str): s3:// url
                filename (str): name of destination file (absolute path)

            Returns: Nothing
            Raises: Exception
        '''
        s3   = self.connection(connection_type='s3')

        log.debug("Fetching {} to {}".format(url, filename))
        m = self.S3URL_RE.match(url)
        if not m:
            raise vFXTConfigurationException("Unknown url format: {}".format(url))

        bucket_name, path = m.groups()
        sig_path     = path + '.sig'
        sig_filename = filename + '.sig'
        bucket       = _aws_do(s3.get_bucket, bucket_name)
        obj          = _aws_do(bucket.get_key, path)
        if not obj:
            raise vFXTConfigurationException("No such object: {}".format(url))

        # check sig
        if os.access(sig_filename, os.F_OK) and os.access(filename, os.F_OK):
            sig_filename_tmp = sig_filename + '.tmp'
            with open(sig_filename_tmp, 'w') as f:
                k = bucket.get_key(sig_path)
                if k:
                    k.get_contents_to_file(f)
            sig_cmp = filecmp.cmp(sig_filename, sig_filename_tmp)
            os.unlink(sig_filename_tmp)
            if sig_cmp:
                log.debug('Signature {} up to date'.format(sig_path))
                return # cached, no download necessary
        # fetch sig
        sig_obj = _aws_do(bucket.get_key, sig_path)
        if sig_obj:
            with open(sig_filename, 'w') as f:
                sig_obj.get_contents_to_file(f)
        # fetch object
        with open(filename, 'w') as f:
            obj.get_contents_to_file(f)

    def _destroy_installation_image(self, name):
        '''Destroy an installation image

            Arguments:
            name (str): name of the AMI
        '''
        log.info("Destroying installation image {}".format(name))
        conn = self.connection()
        try:
            image = _aws_do(conn.get_image, name).id
        except Exception as e:
            log.debug(e)
            log.debug("Failed to get image {} by id, trying by name".format(name))
            try:
                image = _aws_do(conn.get_all_images, filters={'name': name})[0].id
            except Exception as e:
                log.debug(e)
                raise vFXTServiceFailure("Failed to find installation image {}".format(name))
        try:
            _aws_do(conn.deregister_image, image, delete_snapshot=True)
        except Exception as e:
            raise vFXTServiceFailure("Failed to destroy image {}: {}".format(name, e))

    def _cache_to_disk_config(self, cache_size, machine_type=None, disk_type=None): #pylint: disable=unused-argument
        '''For a given cache size, output the default data disk count and size

            Arguments:
                cache_size (int): vFXT cluster node cache size in GB
                machine_type (str, optional): vFXT cluster node machine type
                disk_type (str, optional): vFXT cluster node disk type

            Returns:
                tuple (disk count, size per disk)
        '''
        count = 10 if cache_size >= 1000 else 1
        return tuple([count, int(cache_size / count)])

    def _get_all_subnets(self):
        '''Return a list of subnets for the current configuration
        '''
        vpc = self.connection(connection_type='vpc')
        return _aws_do(vpc.get_all_subnets)

    def _get_default_image(self, region=None):
        '''Get the default image from the defaults

            Arguments:
                region (str, optional): AWS region

            This may not be available if we are unable to fetch the defaults.
        '''
        try:
            return self.defaults[region or self.region]['current']
        except Exception:
            raise vFXTConfigurationException("You must provide a root disk image.")


def _aws_do_non_idempotent(function, *args, **kwargs):
    '''Retry boto operation with exponential backoff, failing quickly on
       application errors.

       This is intended to fail fast so we do not create duplicate resources.
       For any idempotent operations use _aws_do.

        Arguments:
            function (function): function to call
            *args, **kwargs: arguments to pass to function

        Calls vFXT.service.backoff() with the error counter
    '''
    errors = 0
    while True:
        try:
            return function(*args, **kwargs)
        except boto.exception.BotoServerError as e:
            log.debug("_aws_do_non_idempotent exception: {}".format(e))
            errors += 1
            # probably could be only 503 but boto also looks for 500
            # Throttling is 400
            throttled = True if e.status == 400 and 'Throttling' in str(e) else False
            if e.status < 500 and not throttled: raise # #pylint: disable=no-member

            time.sleep(backoff(errors))

            # give up after our max retry count
            if errors > Service.BOTO_503_RETRIES: raise


def _aws_do(function, *args, **kwargs):
    '''Retry boto operation with exponential backoff

        Arguments:
            function (function): function to call
            *args, **kwargs: arguments to pass to function

        Calls vFXT.service.backoff() with the error counter
    '''
    errors = 0
    while True:
        try:
            return function(*args, **kwargs)
        except Exception as e:
            log.debug("_aws_do exception: {}".format(e))
            errors += 1

            # probably could be only 503 but boto also looks for 500
            if isinstance(e, boto.exception.BotoServerError):
                # Throttling is 400
                throttled = True if e.status == 400 and 'Throttling' in str(e) else False # pylint: disable=no-member
                if e.status < 500 and not throttled: raise # #pylint: disable=no-member

            time.sleep(backoff(errors))

            # give up after our max retry count
            if errors > Service.BOTO_503_RETRIES: raise
