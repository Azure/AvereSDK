#! /usr/bin/env python2.7
# Copyright (c) 2015-2017 Avere Systems, Inc.  All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
import os
import argparse
import logging
import getpass
import code
import uuid
import vFXT
import vFXT
from vFXT import Cluster
from vFXT.service import *
from vFXT import Cidr

def _validate_ip(addr):
    addr = addr.split('/')[0]
    octets = [n for n in addr.split('.') if n != '']
    if len(octets) != 4:
        raise argparse.ArgumentTypeError("malformed IP address: {}".format(addr))
    try:
        if  all([v <= 255 and v >= 0 for v in [int(n) for n in octets]]):
            return addr
    except:
        raise argparse.ArgumentTypeError("malformed IP address: {}".format(addr))

def _validate_url(url):
    import urlparse
    parsed = urlparse.urlparse(url)
    if parsed.hostname:
        return url
    raise argparse.ArgumentTypeError("malformed URL: {}".format(url))

def _get_user_shelveable(service, user):#pylint: disable=unused-argument
    raise NotImplementedError()

def _get_user_shelveable_aws(service, user):
    search = {'tag:shelve': 'yes', 'tag:Owner': user}
    return [i.id for i in service.find_instances(search)]

def _get_user_shelveable_gce(service, user):
    shelveable = []
    for instance in service.find_instances():
        if 'metadata' not in instance:
            continue
        if 'items' not in instance['metadata']:
            continue
        metadata   = instance['metadata']['items']
        has_shelve = 'shelve' in [attr['key'] for attr in metadata]
        is_user    = user in [attr['value'] for attr in metadata if attr['key'] == 'Owner']
        if is_user and has_shelve:
            shelveable.append(instance['name'])
    return shelveable

def _get_cluster(service, logger, args):
    cluster = None
    try:
        if not all([args.management_address, args.admin_password]):
            raise vFXTConnectionFailure("No connection information")
        logger.info("Loading cluster information from {}".format(args.management_address))
        if args.instances:
            logger.info("If this cluster is offline, the instance list will be used instead")
        cluster = Cluster.load(service, mgmt_ip=args.management_address, admin_password=args.admin_password)
    except vFXTConnectionFailure as load_exception:
        if not args.instances and not args.mine:
            logger.info("Unable to connect to cluster.  It may be offline")
            return None

        try:
            if not args.user:
                args.user = getpass.getuser()
            if not args.instances and args.mine:
                args.instances = service._get_user_shelveable(service, args.user)
            if not args.instances:
                logger.error("No usable instances")
                return None
            cluster = Cluster(service, nodes=args.instances)
            if args.admin_password:
                cluster.admin_password = args.admin_password
            if args.management_address:
                cluster.mgmt_ip = args.management_address
        except Exception as init_exception:
            logger.exception(init_exception)
            return None
    except Exception as load_exception:
        logger.exception(load_exception)
        raise load_exception

    return cluster

def _add_nfs_corefiler(cluster, logger, args):
    corefiler = args.core_filer or 'nfs'
    server = args.nfs_mount.split(':')[0]
    logger.info("Creating core filer {}".format(corefiler))
    cluster.attach_corefiler(corefiler, server)
    return corefiler

def _add_bucket_corefiler(cluster, logger, args):
    bucketname = args.bucket or "{}-{}".format(cluster.name, str(uuid.uuid4()).lower().replace('-', ''))[0:63]
    corefiler  = args.core_filer or cluster.service.__module__.split('.')[-1]

    bucket_opts = {
        'crypto_mode': 'DISABLED' if args.disable_bucket_encryption else None,
        'compress_mode': 'DISABLED' if args.disable_bucket_compression else None,
    }

    if not args.bucket:
        logger.info("Creating corefiler {} with new bucket: {}".format(corefiler, bucketname))
        if args.govcloud:
            cluster.service.create_bucket(bucketname, storage_class=args.storage_class)
            cluster.attach_bucket(corefiler, '{}:{}'.format(bucketname, cluster.service.region), **bucket_opts)
        else:
            cluster.make_test_bucket(bucketname=bucketname, corefiler=corefiler, storage_class=args.storage_class, **bucket_opts)
    else: # existing bucket
        logger.info("Attaching an existing bucket {} to corefiler {}".format(bucketname, corefiler))
        bucket_opts['existing_data'] = args.bucket_not_empty
        cluster.attach_bucket(corefiler, bucketname, master_password=args.admin_password, **bucket_opts)
    return corefiler

def main():
    parser = argparse.ArgumentParser(description="Create an Avere vFXT cluster", version=vFXT.__version__)

    # actions
    action_opts = parser.add_mutually_exclusive_group(required=True)
    action_opts.add_argument("--create", help="Create a new cluster", action="store_true")
    action_opts.add_argument("--destroy", help="Destroy a cluster", action="store_true")
    action_opts.add_argument("--stop", help="Stop a cluster", action="store_true")
    action_opts.add_argument("--start", help="Start a cluster", action="store_true")
    action_opts.add_argument("--add-nodes", help="Add nodes to an existing cluster", action="store_true")
    action_opts.add_argument("--shelve", help=argparse.SUPPRESS, action="store_true")
    action_opts.add_argument("--unshelve", help=argparse.SUPPRESS, action="store_true")
    action_opts.add_argument("--upgrade", help='Upgrade a cluster', action="store_true")
    action_opts.add_argument("--check", help="Run checks for api access and quotas", action="store_true")
    action_opts.add_argument("--interact", help="Use the Python interpreter", action="store_true")

    # service arguments
    parser.add_argument("--cloud-type", help="the cloud provider to use", choices=['aws', 'gce'], required=True)
    parser.add_argument('--s3-access-key', help='custom or specific S3 access key', default=None)
    parser.add_argument('--s3-secret-key', help='custom or specific S3 secret key', default=None)
    parser.add_argument('--s3-profile',    help='custom or specific S3 profile',       default=None)
    parser.add_argument("--on-instance", help="Assume running on instance and query for instance credentials", action="store_true")
    parser.add_argument("--from-environment", help="Assume credentials from local configuration/environment", action="store_true")
    parser.add_argument("--image-id", help="Root disk image ID used to instantiate nodes")


    # service arguments (AWS)
    aws_opts = parser.add_argument_group('AWS specific options', 'Options applicable for --cloud-type aws')
    aws_opts.add_argument("--access-key", help="AWS Access key", default=None)
    aws_opts.add_argument("--secret-key", help="AWS Secret key", default=None)
    aws_opts.add_argument("--profile", help="Profile to use when connecting to EC2/VPC/IAM", default=None)

    aws_opts.add_argument("--security-group", help="security group ID for the cluster (sg-xxxx), space delimited for multiple", default=None)
    aws_opts.add_argument("--region", help="AWS region in which to create the cluster")
    aws_opts.add_argument("--iam-role", help="IAM role to assign to the cluster", default=None)
    aws_opts.add_argument("--iam-host", help="IAM host", default=None)
    aws_opts.add_argument("--arn", help="ARN string", default=None)
    aws_opts.add_argument("--ephemeral", help="Use EC2 ephemeral disks for cache (WARNING: RISKS DATA LOSS)", action="store_true")
    aws_opts.add_argument("--placement-group", help="Name of a placement group to use. ", default=None, action="store")
    aws_opts.add_argument("--dedicated-tenancy", help="Start all instances with dedicated tenancy", action="store_true")
    aws_opts.add_argument("--subnet", nargs="+", help="One or more subnet names (subnet-xxxx)")
    aws_opts.add_argument("--aws-tag", help="Key:Value pairs to be added as tags", action='append', default=None)
    aws_opts.add_argument("--govcloud", help="Set defaults for AWS GovCloud", action='store_true')
    aws_opts.add_argument("--no-disk-encryption", help="Disable use of encryption with data disks", action='store_true')
    aws_opts.add_argument("--no-ebs-optimized", help="Disable use of EBS optimization", action='store_true')
    aws_opts.add_argument("--kms-key-id", help=argparse.SUPPRESS, action=None) # KMS key ID (ARN format)

    # service arguments (GCE)
    gce_opts = parser.add_argument_group('GCE specific options', 'Options applicable for --cloud-type gce')
    gce_opts.add_argument("--client-email", help="OATH2 Client email if using the p12 key file", default='default')
    gce_opts.add_argument("--project", help="Project name", default=None)
    gce_opts.add_argument("--zone", nargs="+", help="One or more zone names (us-central1-a)", type=str, default=None)
    gce_opts.add_argument("--network", help="Network name", default=None)
    gce_opts.add_argument("--subnetwork", help="Subnetwork name", default=None)
    gce_opts.add_argument("--key-file", help="OATH2 service account P12/JSON key file", default=None)
    gce_opts.add_argument("--local-ssd", help="Use local-ssd disks for cache (WARNING: RISKS DATA LOSS)", action="store_true")
    gce_opts.add_argument("--metadata", help="Key:Value metadata pairs", action='append')
    gce_opts.add_argument("--gce-tag", help="GCE instance tag", action='append', default=None)
    gce_opts.add_argument("--service-account", help="GCE service account to use for the cluster (or default)", type=str, default=None)
    gce_opts.add_argument("--scopes", nargs='+', help="GCE scopes to use for the cluster", type=_validate_url, default=None)
    gce_opts.add_argument("--instance-addresses", nargs='+', help="GCE instance addresses to use", type=_validate_ip, default=None)
    gce_opts.add_argument("--storage-class", help="GCE bucket storage class", default=None, type=str)

    # optional arguments
    parser.add_argument("-d", "--debug", help="Give verbose feedback", action="store_true")
    parser.add_argument("--skip-cleanup", help="Do not cleanup buckets, volumes, instances, etc on failure", action="store_true")
    parser.add_argument("--wait-for-state", help="When done configuring the vFXT cluster wait for cluster state red, yellow, or green. The default is yellow.",
                    choices=['red', 'yellow', 'green'], default="yellow")
    parser.add_argument("--poll-time", help=argparse.SUPPRESS, default=1, type=int) # seconds per poll when waiting
    parser.add_argument('--proxy-uri', help='Proxy resource for API calls, example http://user:pass@172.16.16.20:8080/', metavar="URL", type=_validate_url)
    parser.add_argument('--ssh-key', help="SSH key for cluster authentication (path to public key file for GCE, key name for AWS)", type=str, default=None)

    shelve_opts = parser.add_argument_group()
    shelve_opts.add_argument('--mine', help=argparse.SUPPRESS, action="store_true")
    shelve_opts.add_argument('--user', help=argparse.SUPPRESS, metavar="USERNAME")

    # cluster configuration
    cluster_opts = parser.add_argument_group('Cluster configuration', 'Options for cluster configuration')
    cluster_opts.add_argument("--cluster-name", help="Name for the cluster (also used to tag resources)")
    cluster_opts.add_argument("--instances", nargs="+", help="Instance IDs of cluster nodes (required by --start or if the cluster is offline)", type=str)
    cluster_opts.add_argument("--instance-type", help="Type of instances used to instantiate nodes")
    cluster_opts.add_argument("--admin-password", help="Admin password for cluster",
                        default=None)
    cluster_opts.add_argument("--management-address", metavar="IP_ADDR",
                        help="IP address for management of the cluster",
                        type=_validate_ip)
    cluster_opts.add_argument("--nodes", help="Number of nodes to create in the cluster (minimum of 3 for create)", type=int)
    cluster_opts.add_argument("--node-cache-size", help="Size of data cache per node (in GB).  This defines data-disk-count and data-disk-size optimally with the provided cache size.", default=0, type=int)
    cluster_opts.add_argument("--data-disk-count", help="Number of data disk volumes per node to create for the vFXT cluster",
                        default=None, type=int)
    cluster_opts.add_argument("--data-disk-type", help="Type of volumes to create for the vFXT cluster cache.  AWS values are gp2 (default), io1, or standard.  GCE values are pd-standard, pd-ssd, or local-ssd.", default=None)
    cluster_opts.add_argument("--data-disk-iops", help="Number of sustained IOPS (for volume type io1)",
                    default=None, type=int)
    cluster_opts.add_argument("--data-disk-nvme", help="Use the NVME interface instead of SCSI (GCE local-ssd only)", action='store_true')
    cluster_opts.add_argument("--data-disk-size", help="Size of the cache data disk (in GB)",
                        default=None, type=int)
    cluster_opts.add_argument("--root-size", help="Total size of the boot disk (in GB)",
                        default=None, type=int)
    cluster_opts.add_argument("--configuration-expiration", help=argparse.SUPPRESS, default=Cluster.CONFIGURATION_EXPIRATION, type=int) # Number of minutes until the cluster.cfg file should expire
    cluster_opts.add_argument('--upgrade-url', help="Url to an AvereOS upgrade packagea")
    cluster_opts.add_argument('--cluster-range', help='IP address range (cidr format) to use for addressing', default=None,
                        type=lambda x: str(Cidr(x)))
    cluster_opts.add_argument('--cluster-proxy-uri', help='Proxy resource for the cluster configuration, example http://user:pass@172.16.16.20:8080/.  NOTE: using the address rather than hostname is preferred in the event DNS is not reachable.', metavar="URL", type=_validate_url)
    cluster_opts.add_argument('--public-address', help=argparse.SUPPRESS, action='store_true')
    cluster_opts.add_argument('--trace-level', help='Trace level for the created cluster', default='', type=str)
    cluster_opts.add_argument('--join-instance-address', help='Join nodes using the instance address rather than the management address', action='store_true')
    cluster_opts.add_argument('--join-wait', help='Time (in seconds) to wait for nodes to join', type=int)
    cluster_opts.add_argument('--cluster-address-range-start', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--cluster-address-range-end', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--cluster-address-range-netmask', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--quick-destroy', help="Skip cleanup steps that prevent data loss", action="store_true")
    cluster_opts.add_argument('--skip-support-configuration', help=argparse.SUPPRESS, action="store_true") # Skip initial support configuration

    # corefiler
    cluster_opts.add_argument("--no-corefiler", help="Skip creating core filer", action='store_true')
    cluster_opts.add_argument("--no-vserver", help="Skip creating default virtual server", action='store_true')
    cluster_opts.add_argument("--bucket", help="S3 or Google Storage bucket to use as the core filer (must be empty), otherwise one will be created")
    cluster_opts.add_argument("--bucket-not-empty", help=argparse.SUPPRESS, action='store_true') # Existing bucket has data in it
    cluster_opts.add_argument("--disable-bucket-encryption", help=argparse.SUPPRESS, action='store_true') # Disable the use of encryption for files in the bucket
    cluster_opts.add_argument("--disable-bucket-compression", help=argparse.SUPPRESS, action='store_true') # Disable the use of compression for files in the bucket
    cluster_opts.add_argument("--nfs-mount", help="NFS mountpoint to use as the core filer (host:/path)")
    cluster_opts.add_argument("--core-filer", help="Name of the core filer to create")
    cluster_opts.add_argument("--subdir", help="NFS Export subdirectory (if / is the only export)", type=str, default='')
    cluster_opts.add_argument("--junction", help="Path of the vserver junction (must start with /, defaults to end of NFS export path or cloud vendor name)", type=str, default='')
    cluster_opts.add_argument("--vserver", help="Name of the vserver to create (defaults to vserver)", default='vserver')
    cluster_opts.add_argument('--vserver-address-range-start', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--vserver-address-range-end', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--vserver-address-range-netmask', help=argparse.SUPPRESS, type=_validate_ip)

    args = parser.parse_args()

    # logging
    logging.basicConfig(format='%(asctime)s - %(name)s:%(levelname)s - %(message)s', datefmt='%Y-%m-%dT%H:%M:%S%z')
    logger = logging.getLogger('vfxt')
    logger.setLevel(logging.INFO)
    if args.debug:
        logging.getLogger(Cluster.__module__).setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        logging.getLogger(Cluster.__module__).setLevel(logging.INFO)
    logger.info("Using vFXT version {}".format(vFXT.__version__))

    # Service setup
    service = None
    if args.cloud_type == 'aws':
        from vFXT.aws import Service
        if args.debug:
            logging.getLogger(Service.__module__).setLevel(logging.DEBUG)
        else:
            logging.getLogger('boto').setLevel(logging.CRITICAL)
            logging.getLogger(Service.__module__).setLevel(logging.INFO)

        # init our service
        if args.on_instance:
            service = Service.on_instance_init(proxy_uri=args.proxy_uri)
            if args.subnet:
                service.subnets = args.subnet
        else:
            if not args.from_environment and not all([args.region, args.access_key, args.secret_key]):
                logger.error("Arguments region, access-key, and secret-key are required")
                parser.exit(1)

            if args.subnet and args.placement_group and len(args.subnet) > 1:
                logger.error("A placement group can't span multiple Availability Zones.")
                parser.exit(1)

            # if not s3 specific keys, use the regular ones
            if not args.s3_access_key:
                args.s3_access_key = args.access_key
            if not args.s3_secret_key:
                args.s3_secret_key = args.secret_key

            if args.govcloud:
                args.arn = 'aws-us-gov'
                args.iam_host = 'iam.us-gov.amazonaws.com'
            if all([args.iam_host, args.arn]):
                if args.arn == 'aws-us-gov' and args.iam_host == 'iam.us-gov.amazonaws.com':
                    args.govcloud = True

            opts = {
                'region': args.region,
                'access_key': args.access_key,
                'secret_access_key': args.secret_key,
                'profile_name': args.profile,
                's3_access_key': args.s3_access_key,
                's3_secret_access_key': args.s3_secret_key,
                's3_profile_name': args.s3_profile,
                'arn': args.arn,
                'iam_host': args.iam_host,
                'subnet': args.subnet,
                'proxy_uri': args.proxy_uri,
                'security_groups': args.security_group,
            }
            if args.from_environment:
                del opts['access_key']
                del opts['secret_access_key']
                if args.profile:
                    opts['profile'] = args.profile
                service = Service.environment_init(**opts)
            else:
                service = Service(**opts)

        # service specific arg setup
        if args.ephemeral:
            args.data_disk_type = 'ephemeral'

        if args.aws_tag:
            args.aws_tag = {n.split(':')[0]: (n.split(':')[1] or '') for n in args.aws_tag if len(n.split(':')) > 1}

        service._get_user_shelveable = _get_user_shelveable_aws

    elif args.cloud_type == 'gce':

        from vFXT.gce import Service
        if args.debug:
            logging.getLogger(Service.__module__).setLevel(logging.DEBUG)
        else:
            logging.getLogger(Service.__module__).setLevel(logging.INFO)

        if args.on_instance:
            service = Service.on_instance_init(proxy_uri=args.proxy_uri)
            if args.network:
                service.network_id = args.network
            if args.zone:
                service.zones = args.zone
            if args.subnetwork:
                service.subnetwork_id = args.subnetwork
        else:
            if args.from_environment:
                if not all([args.project, args.network, args.zone]):
                    logger.error("Arguments project, network, and zone are required with environment")
                    parser.exit(1)
            else:
                if not all([args.network, args.zone, args.key_file]):
                    logger.error("Arguments network, zone, and key or key-file are required")
                    parser.exit(1)
                if not args.key_file and not all([args.client_email, args.project]):
                    logger.error("Arguments client_email and project are required with key")
                    parser.exit(1)

            opts = {
                'client_email': args.client_email,
                'key_file': args.key_file,
                'zone': args.zone,
                'project_id': args.project,
                'network_id': args.network,
                'subnetwork_id': args.subnetwork,
                's3_access_key': args.s3_access_key,
                's3_secret_access_key': args.s3_secret_key,
                'proxy_uri': args.proxy_uri,
            }
            if args.from_environment:
                service = Service.environment_init(**opts)
            else:
                service = Service(**opts)

        if args.local_ssd:
            args.data_disk_type = 'local-ssd'

        if args.metadata:
            args.metadata = {n.split(':')[0]: (n.split(':')[1] or '') for n in args.metadata if len(n.split(':')) > 1}
        else:
            args.metadata = {}

        if args.storage_class:
            if not args.storage_class in Service.STORAGE_CLASSES:
                logger.error("Invalid storage class.  Must be one of {}".format(', '.join(Service.STORAGE_CLASSES)))
                parser.exit(1)

        if args.ssh_key:
            try:
                with open(args.ssh_key) as f:
                    args.metadata['ssh-keys'] = 'admin:{}'.format(f.read())
                args.ssh_key = None # we pass it via metadata
            except Exception as e:
                logger.error("Failed to read SSH key: {}".format(e))
                parser.exit(1)

        service._get_user_shelveable = _get_user_shelveable_gce

    # generic service options
    service.POLLTIME = args.poll_time
    service.private_range = args.cluster_range

    if args.node_cache_size:
        if any([args.data_disk_count, args.data_disk_size]):
            logger.warn("Overriding --data-disk-count and --data-disk-size with --node-cache-size")
        disk_config = service._cache_to_disk_config(args.node_cache_size, disk_type=args.data_disk_type)
        args.data_disk_count = disk_config[0]
        args.data_disk_size = disk_config[1]
        logger.debug("Cache size {} specified, setting disk count and size to {}, {}".format(args.node_cache_size, args.data_disk_count, args.data_disk_size))

    if args.create:
        # run a service check first
        service.check()

        # minimum args for create
        if not all([args.instance_type, args.cluster_name, args.admin_password]):
            logger.error("Arguments instance-type, cluster-name, and admin-password are required")
            parser.exit(1)
        if args.nodes and args.nodes < 3: # we default below if nothing was specified
            logger.error("Cluster sizes below 3 are not supported")
            parser.exit(1)
        # cluster create options
        options = {
            'size': args.nodes or 3,
            'data_disk_count': args.data_disk_count,
            'data_disk_size': args.data_disk_size,
            'data_disk_type': args.data_disk_type,
            'data_disk_iops': args.data_disk_iops,
            'data_disk_nvme': args.data_disk_nvme,
            'root_image': args.image_id,
            'root_size': args.root_size,
            'iamrole': args.iam_role,
            'placement_group': args.placement_group,
            'dedicated_tenancy': args.dedicated_tenancy,
            'wait_for_state': args.wait_for_state,
            'security_group_ids': args.security_group,
            'network_security_group': args.security_group,
            'config_expiration': args.configuration_expiration,
            'tags': args.aws_tag or args.gce_tag,
            'metadata': args.metadata,
            'skip_cleanup': args.skip_cleanup,
            'skip_support_configuration': args.skip_support_configuration,
            'proxy_uri': args.cluster_proxy_uri,
            'disk_encryption': not args.no_disk_encryption,
            'ebs_optimized': None if not args.no_ebs_optimized else not args.no_ebs_optimized, # use machine defaults
            'auto_public_address': args.public_address,
            'management_address': args.management_address,
            'address_range_start': args.cluster_address_range_start,
            'address_range_end': args.cluster_address_range_end,
            'address_range_netmask': args.cluster_address_range_netmask,
            'instance_addresses': args.instance_addresses,
            'trace_level': args.trace_level,
            'key_name': args.ssh_key, # aws ssh key
            'join_instance_address': args.join_instance_address,
            'join_wait': args.join_wait or None,
            'service_account': args.service_account,
            'scopes': args.scopes,
        }
        # prune out unfortunate command line defaults
        options = {k: v for k, v in options.iteritems() if v is not None and v != ''}

        logger.info("Creating {} cluster {}".format(args.instance_type, args.cluster_name))
        try:
            cluster = Cluster.create(service, args.instance_type, args.cluster_name, args.admin_password, **options)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to create cluster: {}".format(e))
            parser.exit(1)

        corefiler_name = None
        if not args.no_corefiler:
            try:
                if args.nfs_mount:
                    corefiler_name = _add_nfs_corefiler(cluster, logger, args)
                else:
                    corefiler_name = _add_bucket_corefiler(cluster, logger, args)
            except Exception as e:
                if args.debug:
                    logger.exception(e)
                logger.error("Failed to configure core filer: {}".format(e))
                if not args.skip_cleanup:
                    cluster.destroy(quick_destroy=True, remove_buckets=False if args.bucket else True) # will not remove a non-empty bucket
                parser.exit(1)

        if not args.no_vserver:
            try:
                logger.info("Creating vserver {}".format(args.vserver))
                vserver_opts = {
                    'netmask': args.vserver_address_range_netmask,
                    'start_address': args.vserver_address_range_start,
                    'end_address': args.vserver_address_range_end
                }
                cluster.add_vserver(args.vserver, **vserver_opts)
                if corefiler_name:
                    logger.info("Creating vserver junction {}".format(corefiler_name))
                    junction_opts = {
                        'path': args.junction
                    }
                    if args.nfs_mount:
                        mount = args.nfs_mount.split(':')[-1]
                        junction_opts['path'] = args.junction or '/{}'.format(mount.split(os.sep)[-1])
                        junction_opts['export'] = mount
                        junction_opts['subdir'] = args.subdir
                    cluster.add_vserver_junction(args.vserver, corefiler_name, path=args.junction)
            except Exception as e:
                if args.debug:
                    logger.exception(e)
                logger.error("Failed to configure vserver: {}".format(e))
                if not args.skip_cleanup:
                    cluster.destroy(quick_destroy=True, remove_buckets=False if args.bucket else True) # will not remove a non-empty bucket
                parser.exit(1)

        cluster_version = cluster.xmlrpc().cluster.get()['activeImage']
        logger.info("{} version {}".format(cluster.name, cluster_version))
        logger.info("{} management address: {}".format(cluster.name, cluster.mgmt_ip))
        logger.info("{} nodes: {}".format(cluster.name, ' '.join([n.id() for n in cluster.nodes])))
        logger.info("Complete")

    elif args.start:
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)

        if cluster.is_on():
            logger.error("Cluster is already running.")
            parser.exit(1)

        node_names = ', '.join([i.name() for i in cluster.nodes])
        logger.info("Starting cluster with nodes {}".format(node_names))
        try:
            cluster.start()
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to start cluster: {}".format(e))
            parser.exit(1)

        if all([args.management_address, args.admin_password]):
            cluster.mgmt_ip        = args.management_address
            cluster.admin_password = args.admin_password
            if args.wait_for_state:
                cluster.wait_for_healthcheck(state=args.wait_for_state, conn_retries=20)
        logger.info("Complete")

    elif args.stop:
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)

        if cluster.is_off():
            logger.error("Cluster is already stopped.")
            parser.exit(1)

        node_names = ', '.join([i.name() for i in cluster.nodes])
        logger.info("Stopping cluster with nodes {}".format(node_names))
        try:
            cluster.stop()
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to stop cluster: {}".format(e))
            parser.exit(1)
        logger.info("Complete")

    elif args.destroy:
        # minimum args for destroy
        if not all([args.management_address, args.admin_password]):
            logger.error("Arguments management-address and admin-password are required")
            parser.exit(1)

        cluster = _get_cluster(service, logger, args)
        if not cluster:
            logger.error("Cluster not found.")
            parser.exit(1)

        node_names = ', '.join([i.name() for i in cluster.nodes])
        logger.info("Destroying cluster with nodes {}".format(node_names))
        try:
            cluster.destroy(quick_destroy=args.quick_destroy)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to destroy cluster: {}".format(e))
            parser.exit(1)
        logger.info("Complete")

    elif args.shelve:
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)

        if cluster.is_shelved():
            logger.error("Nodes are already shelved.")
            parser.exit(1)

        node_names = ' '.join([i.name() for i in cluster.nodes])
        logger.info("Shelving nodes {}".format(node_names))
        cluster.shelve()
        logger.info("Completed shelving nodes {}".format(node_names))

    elif args.unshelve:
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)

        if not cluster.is_shelved():
            logger.error("Nodes are not shelved.")
            parser.exit(1)

        node_names = ' '.join([i.name() for i in cluster.nodes])
        logger.info("Unshelving nodes {}".format(node_names))
        try:
            cluster.unshelve(count_override=args.data_disk_count, size_override=args.data_disk_size, type_override=args.data_disk_type, kms_key_id=args.kms_key_id)
        except Exception as e:
            logger.exception(e)
            cluster.refresh()
            if not cluster.is_on():
                cluster.shelve()
            logger.error("Failed to unshelve cluster")
            parser.exit(1)

        # if a real cluster, we can run healthcheck
        if all([args.management_address, args.admin_password]) and not args.instances:
            cluster.mgmt_ip        = args.management_address
            cluster.admin_password = args.admin_password
            if args.wait_for_state:
                cluster.wait_for_healthcheck(state=args.wait_for_state, conn_retries=20)

        logger.info("Completed unshelving nodes {}".format(node_names))

    elif args.add_nodes:
        if not all([args.nodes, args.management_address, args.admin_password]):
            logger.error("Arguments nodes, management-address, and admin-password are required")
            parser.exit(1)
        cluster = _get_cluster(service, logger, args)
        if not cluster:
            logger.error("Cluster not found.")
            parser.exit(1)

        options = {
            'root_image': args.image_id,
            'root_size': args.root_size,
            'data_disk_count': args.data_disk_count,
            'data_disk_size': args.data_disk_size,
            'data_disk_type': args.data_disk_type,
            'data_disk_iops': args.data_disk_iops,
            'tags': args.aws_tag or args.gce_tag,
            'metadata': args.metadata,
            'skip_cleanup': args.skip_cleanup,
            'machine_type': args.instance_type,
            'auto_public_address': args.public_address,
            'join_wait': args.join_wait or None,
            'service_account': args.service_account,
        }
        # prune out unfortunate command line defaults
        options = {k: v for k, v in options.iteritems() if v is not None and v != ''}

        try:
            count = args.nodes or 1
            logger.info("Adding {} node(s) to {}.".format(count, cluster.name))
            cluster.add_nodes(count, **options)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to add nodes to cluster: {}".format(e))
            parser.exit(1)

        logger.info("Rebalancing directory managers")
        try:
            cluster.rebalance_directory_managers()
        except vFXTStatusFailure as e:
            logger.error(e)
            if 'A directory manager rebalance operation is already scheduled' in e:
                parser.exit(1)
        if args.wait_for_state:
            cluster.wait_for_healthcheck(state=args.wait_for_state)
        logger.info("Complete")

    elif args.interact:
        from vFXT.serviceInstance import ServiceInstance # handy import #pylint: disable=unused-variable
        banner = "\n--- Service object available as 'service' ---\n"
        local = {}
        local.update(globals())
        local.update(locals())
        code.interact(local=local, banner=banner)

    elif args.upgrade:
        if not args.upgrade_url:
            logger.error("Provide a URL from which to upgrade")
            parser.exit(1)
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)
        try:
            cluster.upgrade(args.upgrade_url)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to upgrade cluster: {}".format(e))
            parser.exit(1)
        if args.wait_for_state:
            cluster.wait_for_healthcheck(state=args.wait_for_state)

    elif args.check:
        opts = {
            'instances': args.nodes,
            'machine_type': args.instance_type,
            'data_disk_type': args.data_disk_type,
            'data_disk_size': args.data_disk_size,
            'data_disk_count': args.data_disk_count
        }
        service.check(**opts)
    else:
        parser.print_help()
        parser.exit(1)


if __name__ == '__main__':
    main()
