#! /usr/bin/env python
# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
from urllib import parse as urlparse
from future.utils import viewitems
import argparse
import base64
import logging
import getpass
import os
import ssl
import sys
import uuid

import vFXT
from vFXT import Cluster
from vFXT.service import vFXTStatusFailure, vFXTConnectionFailure
from vFXT import Cidr

def _validate_ip(addr):
    addr = addr.split('/')[0]
    octets = [n for n in addr.split('.') if n != '']
    if len(octets) != 4:
        raise argparse.ArgumentTypeError("malformed IP address: {}".format(addr))
    try:
        if all([0 <= v <= 255 for v in [int(n) for n in octets]]):
            return addr
        raise ValueError(addr)
    except Exception:
        raise argparse.ArgumentTypeError("malformed IP address: {}".format(addr))

def _validate_url(url):
    parsed = urlparse.urlparse(url)
    if parsed.hostname:
        return url
    raise argparse.ArgumentTypeError("malformed URL: {}".format(url))

def _validate_ascii(s):
    try:
        _ = s.encode('ascii')
        return s
    except Exception:
        raise argparse.ArgumentTypeError("Value must be ASCII: {}".format(s))

def _validate_writeable_path(p):
    f = None
    try:
        f = open(p, 'wb')
        return p
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid file {}: {}".format(p, e))
    finally:
        if f:
            f.close()

def _get_user_shelveable(service, user):  # pylint: disable=unused-argument
    raise NotImplementedError()

def _get_user_shelveable_azure(service, user):
    shelveable = []
    for inst in service.find_instances():
        if 'tags' not in inst:
            continue
        if 'shelve' not in inst['tags']:
            continue
        if 'owner' not in inst['tags']:
            continue
        if inst['tags']['owner'] == user:
            shelveable.append(inst['name'])
    return shelveable

def _get_cluster(service, logger, args):
    cluster = None
    try:
        if not all([args.management_address, args.admin_password]):
            raise vFXTConnectionFailure("No management address or admin password, unable to connect to the cluster")
        logger.info("Loading cluster information from {}".format(args.management_address))
        if args.instances:
            logger.info("If this cluster is offline, the instance list will be used instead")
        cluster = Cluster.load(service, mgmt_ip=args.management_address, admin_password=args.admin_password)
    except vFXTConnectionFailure as load_exception:
        if not args.instances and not args.mine:
            logger.error(load_exception)
            logger.error("Unable to connect to cluster.  It may be offline")
            return None

        try:
            if not args.instances and args.mine:
                if not args.user:
                    args.user = getpass.getuser()
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
        raise

    return cluster

def _add_nfs_corefiler(cluster, logger, args):
    corefiler = args.core_filer or 'nfs'
    server = args.nfs_mount.split(':')[0]
    logger.info("Creating core filer {}".format(corefiler))

    options = {
        'nfs_type': args.nfs_type,
    }
    cluster.attach_corefiler(corefiler, server, **options)
    return corefiler

def _add_bucket_corefiler(cluster, logger, args):
    bucketname = args.bucket or "{}-{}".format(cluster.name, str(uuid.uuid4()).lower().replace('-', ''))[0:63]
    corefiler = args.core_filer or cluster.service.__module__.split('.')[-1]

    bucket_opts = {
        'crypto_mode': 'DISABLED' if args.disable_bucket_encryption else None,
        'compress_mode': 'DISABLED' if args.disable_bucket_compression else None,
        'https': 'no' if args.disable_bucket_https else None,
        'https_verify_mode': 'DISABLED' if (args.disable_bucket_https or args.disable_bucket_https_verify) else None,
    }
    if args.core_filer_encryption_password:
        # if unset we use the cluster admin password
        bucket_opts['master_password'] = args.core_filer_encryption_password

    if args.cloud_type == 'azure':
        bucketname = '{}/{}'.format(cluster.service.storage_account, bucketname)
        if args.azure_storage_suffix:
            bucket_opts['serverName'] = '{}.blob.{}'.format(cluster.service.storage_account, args.azure_storage_suffix)

    key = None # encryption key data
    if not args.bucket:
        logger.info("Creating corefiler %s with new cloud storage: %s", corefiler, bucketname)
        key = cluster.make_test_bucket(bucketname=bucketname, corefiler=corefiler, **bucket_opts)
    else: # existing bucket
        logger.info("Attaching an existing cloud storage {} to corefiler {}".format(bucketname, corefiler))
        bucket_opts['existing_data'] = args.bucket_not_empty
        key = cluster.attach_bucket(corefiler, bucketname, **bucket_opts)

    if key and args.core_filer_key_file:
        try:
            with open(args.core_filer_key_file, 'wb') as f:
                f.write(base64.b64decode(key['recoveryFile']))
            logger.info("Saved encryption key for {} to {}".format(bucketname, args.core_filer_key_file))
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to save key file to {}: {}".format(args.core_filer_key_file, e))
    elif key: # we only get a key if crypto mode is enabled... so if we didn't save it emit a warning
        logger.warning("*** IT IS STRONGLY RECOMMENDED THAT YOU CREATE A NEW CLOUD ENCRYPTION KEY AND SAVE THE")
        logger.warning("*** KEY FILE (AND PASSWORD) BEFORE USING YOUR NEW CLUSTER.  WITHOUT THESE, IT WILL NOT")
        logger.warning("*** BE POSSIBLE TO RECOVER YOUR DATA AFTER A FAILURE")
        logger.warning("Do this at https://{}/avere/fxt/cloudFilerKeySettings.php".format(cluster.mgmt_ip))

    return corefiler

def main():
    parser = argparse.ArgumentParser(description="Create an Avere vFXT cluster")

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
    action_opts.add_argument("--upgrade-alternate-image", help=argparse.SUPPRESS, action="store_true") # Upgrade the alternate image on a cluster
    action_opts.add_argument("--activate-alternate-image", help=argparse.SUPPRESS, action="store_true") # Activate the alternate image on a cluster
    action_opts.add_argument("--check", help="Run checks for api access and quotas", action="store_true")
    action_opts.add_argument("--telemetry", help="Kick off support upload for a cluster", action="store_true")
    action_opts.add_argument("--interact", help="Use the Python interpreter", action="store_true")

    # service arguments
    parser.add_argument("--cloud-type", help="the cloud provider to use", choices=['azure'], default='azure')
    parser.add_argument("--on-instance", help="Assume running on instance and query for instance credentials", action="store_true")
    parser.add_argument("--from-environment", help="Assume credentials from local configuration/environment", action="store_true")
    parser.add_argument("--image-id", help="Root disk image ID used to instantiate nodes")

    # service arguments (Azure)
    azure_opts = parser.add_argument_group('Azure specific options', 'Options applicable for --cloud-type azure')
    azure_opts.add_argument("--subscription-id", help='Azure subscription identifier', default=None)
    azure_opts.add_argument("--application-id", help='AD application ID', default=None)
    azure_opts.add_argument("--application-secret", help='AD Application secret', default=None)
    azure_opts.add_argument("--tenant-id", help='AD application tenant identifier', default=None)
    azure_opts.add_argument("--resource-group", help='Resource group', default=None)
    azure_opts.add_argument("--network-resource-group", help='Network resource group (if vnet/subnet are different from the vm instance group)', default=None)
    azure_opts.add_argument("--storage-resource-group", help='Storage resource group (if different from the vm instance group)', default=None)
    azure_opts.add_argument("--storage-account", help='Azure Storage account', default=None)
    azure_opts.add_argument("--azure-role", help='Existing Azure role for the cluster (otherwise one is created)', default='Avere Operator')
    azure_opts.add_argument("--azure-identity", help='Existing user created managed identity name (otherwise system assigned identities are used)', default=None)
    azure_opts.add_argument("--location", help='Azure location', default=None)
    azure_opts.add_argument("--azure-network", help='Azure virtual network', default=None)
    azure_opts.add_argument("--azure-subnet", help='Azure virtual network subnet', type=str, default=None)
    azure_opts.add_argument("--azure-zones", nargs="+", help='Azure availability zones', type=str, default=None)
    azure_opts.add_argument("--azure-tag", help="Azure instance tag", action='append', default=None)
    azure_opts.add_argument("--network-security-group", help="Network security group name", default=None)
    azure_opts.add_argument("--enable-boot-diagnostics", help="Azure instance boot diagnostics", action="store_true")
    azure_opts.add_argument("--root-disk-caching", help="Azure root disk caching mode (defaults to None)", choices=['ReadOnly', 'ReadWrite'], default=None)
    azure_opts.add_argument("--data-disk-caching", help="Azure data disk caching mode (defaults to None)", choices=['ReadOnly', 'ReadWrite'], default=None)
    azure_opts.add_argument("--azure-instance-addresses", nargs='+', help="Instance addresses to use rather than dynamically assigned", type=_validate_ip, default=None)
    azure_opts.add_argument("--azure-environment", help="Set the defaults (endpoint base URL and storage suffix) for the Azure environment", choices=['public', 'usgovernment', 'china', 'germany'], default="public")
    azure_opts.add_argument("--azure-endpoint-base-url", help="The base URL of the API endpoint (if non-public Azure)", type=_validate_url, default=None)
    azure_opts.add_argument("--azure-storage-suffix", help="The storage service suffix (if non-public Azure)", default=None)
    azure_opts.add_argument("--ultra-ssd", help="Use UltraSSD disks for cache", action="store_true")
    azure_opts.add_argument("--proximity-placement-group", help="Assign any created VMs to the named Azure proximity placement group", type=str, default=None)

    # optional arguments
    parser.add_argument('--version', action='version', version=vFXT.__version__)
    parser.add_argument("-d", "--debug", help="Give verbose feedback", action="store_true")
    parser.add_argument("--skip-cleanup", help="Do not cleanup buckets, volumes, instances, etc on failure", action="store_true")
    parser.add_argument("--wait-for-state", help="Wait for cluster state after configuration to settle on red, yellow, or green. The default is yellow.", choices=['red', 'yellow', 'green'], default="yellow")
    parser.add_argument("--wait-for-state-duration", help="Number of seconds cluster state must remain for success", type=int, default=30)
    parser.add_argument("--poll-time", help=argparse.SUPPRESS, default=1, type=int) # seconds per poll when waiting
    parser.add_argument('--proxy-uri', help='Proxy resource for API calls, example http://user:pass@172.16.16.20:8080/', metavar="URL", type=_validate_url)
    parser.add_argument('--ssh-key', help="SSH key for cluster authentication (path to public key file for Azure)", type=str, default=None)
    parser.add_argument("--telemetry-mode", help="Telemetry custom mode", type=str, default='gsimin')
    parser.add_argument("--skip-check", help="Skip initial checks for api access and quotas", action="store_true")
    parser.add_argument("--skip-load-defaults", help="Skip fetching online default configuration data", action="store_true")
    parser.add_argument("--log", help="Automatically log the output to the provided file name", type=str, default=None)

    shelve_opts = parser.add_argument_group()
    shelve_opts.add_argument('--mine', help=argparse.SUPPRESS, action="store_true")
    shelve_opts.add_argument('--user', help=argparse.SUPPRESS, metavar="USERNAME")

    # cluster configuration
    cluster_opts = parser.add_argument_group('Cluster configuration', 'Options for cluster configuration')
    cluster_opts.add_argument("--cluster-name", help="Name for the cluster (also used to tag resources)")
    cluster_opts.add_argument("--instances", nargs="+", help="Instance IDs of cluster nodes (required by --start or if the cluster is offline)", type=str)
    cluster_opts.add_argument("--instance-type", help="Type of instances used to instantiate nodes")
    cluster_opts.add_argument("--admin-password", help="Admin password for cluster", default=None, type=_validate_ascii)
    cluster_opts.add_argument("--management-address", metavar="IP_ADDR", help="IP address for management of the cluster", type=_validate_ip)
    cluster_opts.add_argument("--nodes", help="Number of nodes to create in the cluster (minimum of 3 for create)", type=int)
    cluster_opts.add_argument("--node-cache-size", help="Size of data cache per node (in GB).  This defines data-disk-count and data-disk-size optimally with the provided cache size.", default=0, type=int)
    cluster_opts.add_argument("--data-disk-count", help="Number of data disk volumes per node to create for the vFXT cluster", default=None, type=int)
    cluster_opts.add_argument("--data-disk-type", help="Type of volumes to create for the vFXT cluster cache.", default=None)
    cluster_opts.add_argument("--data-disk-iops", help="Number of sustained IOPS (for volume type io1 or UltraSSD_LRS)", default=None, type=int)
    cluster_opts.add_argument("--data-disk-mbps", help="Number of MBps (for volume type UltraSSD_LRS)", default=None, type=int)
    cluster_opts.add_argument("--data-disk-size", help="Size of the cache data disk (in GB)", default=None, type=int)
    cluster_opts.add_argument("--root-size", help="Total size of the boot disk (in GB)", default=None, type=int)
    cluster_opts.add_argument("--configuration-expiration", help=argparse.SUPPRESS, default=Cluster.CONFIGURATION_EXPIRATION, type=int) # Number of minutes until the cluster.cfg file should expire
    cluster_opts.add_argument('--upgrade-url', help="Url to an AvereOS upgrade package")
    cluster_opts.add_argument('--upgrade-non-ha', help="Perform a non-HA upgrade", action="store_true")
    cluster_opts.add_argument('--cluster-range', help='IP address range (cidr format) to use for addressing', default=None, type=lambda x: str(Cidr(x)))
    cluster_opts.add_argument('--cluster-proxy-uri', help='Proxy resource for the cluster configuration, example http://user:pass@172.16.16.20:8080/.  NOTE: using the address rather than hostname is preferred in the event DNS is not reachable.', metavar="URL", type=_validate_url)
    cluster_opts.add_argument('--public-address', help=argparse.SUPPRESS, action='store_true')
    cluster_opts.add_argument('--trace-level', help='Trace level for the created cluster', default='', type=str)
    cluster_opts.add_argument('--timezone', help='Timezone for the created cluster', default='UTC', type=str)
    cluster_opts.add_argument('--join-instance-address', help=argparse.SUPPRESS, action='store_true') # Now the default, do not error for old invocations
    cluster_opts.add_argument('--join-wait', help='Time (in seconds) to wait for nodes to join', type=int)
    cluster_opts.add_argument('--cluster-address-range-start', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--cluster-address-range-end', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--cluster-address-range-netmask', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--quick-destroy', help="Skip cleanup steps that prevent data loss", action="store_true")
    cluster_opts.add_argument('--skip-node-renaming', help=argparse.SUPPRESS, action="store_true") # Skip node renaming

    # corefiler
    cluster_opts.add_argument("--no-corefiler", help="Skip creating core filer", action='store_true')
    cluster_opts.add_argument("--no-vserver", help="Skip creating default virtual server", action='store_true')
    cluster_opts.add_argument("--bucket", "--azurecontainer", help="Azure storageaccount/container to use as the core filer (must be empty), otherwise one will be created", metavar='STORAGE')
    cluster_opts.add_argument("--bucket-not-empty", "--azurecontainer-not-empty", action='store_true', help="Existing storage endpoint has data in it")
    cluster_opts.add_argument("--disable-bucket-encryption", "--disable-azurecontainer-encryption", action='store_true', help="Disable the use of encryption for objects written to the storage endpoint")
    cluster_opts.add_argument("--enable-bucket-encryption", "--enable-azurecontainer-encryption", action='store_true', help=argparse.SUPPRESS) # "Enable the use of encryption for objects written to the storage endpoint"
    cluster_opts.add_argument("--disable-bucket-compression", "--disable-azurecontainer-compression", action='store_true', help="Disable the use of compression for objects written to the storage endpoint")
    cluster_opts.add_argument("--disable-bucket-https", "--disable-azurecontainer-https", action='store_true', help="Disable the use of HTTPS for storage endpoint communication")
    cluster_opts.add_argument("--disable-bucket-https-verify", "--disable-azurecontainer-https-verify", action='store_true', help="Disable HTTPS certificate verification for storage endpoint communication")
    cluster_opts.add_argument("--nfs-mount", help="NFS mountpoint to use as the core filer (host:/path)")
    cluster_opts.add_argument("--nfs-type", help="NFS server type", choices=['NetappNonClustered', 'NetappClustered', 'EmcIsilon'], default=None)
    cluster_opts.add_argument("--core-filer", help="Name of the core filer to create")
    cluster_opts.add_argument("--core-filer-key-file", help="File path to save the encryption key (if encryption is not disabled)", type=_validate_writeable_path, default=None)
    cluster_opts.add_argument("--core-filer-encryption-password", help="The encryption password for the corefiler (defaults to the cluster admin password)", default=None)
    cluster_opts.add_argument("--subdir", help="NFS Export subdirectory (if / is the only export)", type=str, default='')
    cluster_opts.add_argument("--junction", help="Path of the vserver junction (must start with /, defaults to /nfs for NFS exports or cloud vendor name)", type=str, default='')
    cluster_opts.add_argument("--vserver", help="Name of the vserver to create (defaults to vserver)", default='vserver')
    cluster_opts.add_argument('--vserver-address-range-start', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--vserver-address-range-end', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--vserver-address-range-netmask', help=argparse.SUPPRESS, type=_validate_ip)
    cluster_opts.add_argument('--vserver-home-addresses', help=argparse.SUPPRESS, action='store_true') # home the addresses of the vserver across the nodes

    args = parser.parse_args()

    # logging
    logging.basicConfig(format='%(asctime)s - %(name)s:%(levelname)s - %(message)s', datefmt='%Y-%m-%dT%H:%M:%S%z')
    log_file = logging.FileHandler(args.log) if args.log else logging.NullHandler()
    log_file.setFormatter(logging.Formatter('%(asctime)s - %(name)s:%(levelname)s - %(message)s', '%Y-%m-%dT%H:%M:%S%z'))
    logger = logging.getLogger('vfxt')
    logger.setLevel(logging.INFO)
    logger.addHandler(log_file)
    if args.debug:
        logging.getLogger(Cluster.__module__).setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    else:
        logging.getLogger(Cluster.__module__).setLevel(logging.INFO)
    logging.getLogger(Cluster.__module__).addHandler(log_file)
    logger.info("Using vFXT version {}".format(vFXT.__version__))

    # Service setup
    service = None
    if args.cloud_type == 'azure':
        from vFXT.msazure import Service
        if args.debug:
            logging.getLogger(Service.__module__).setLevel(logging.DEBUG)
        else:
            logging.getLogger(Service.__module__).setLevel(logging.INFO)
        logging.getLogger(Service.__module__).addHandler(log_file)

        if args.azure_environment == 'usgovernment':
            args.azure_endpoint_base_url = Service.AZURE_ENVIRONMENTS['AzureUSGovernment']['endpoint']
            args.azure_storage_suffix = Service.AZURE_ENVIRONMENTS['AzureUSGovernment']['storage_suffix']
        if args.azure_environment == 'china':
            args.azure_endpoint_base_url = Service.AZURE_ENVIRONMENTS['AzureChinaCloud']['endpoint']
            args.azure_storage_suffix = Service.AZURE_ENVIRONMENTS['AzureChinaCloud']['storage_suffix']
        if args.azure_environment == 'germany':
            args.azure_endpoint_base_url = Service.AZURE_ENVIRONMENTS['AzureGermanCloud']['endpoint']
            args.azure_storage_suffix = Service.AZURE_ENVIRONMENTS['AzureGermanCloud']['storage_suffix']

        if args.on_instance:
            service = Service.on_instance_init(
                proxy_uri=args.proxy_uri,
                subscription_id=args.subscription_id,
                application_id=args.application_id,
                application_secret=args.application_secret,
                tenant_id=args.tenant_id,
                resource_group=args.resource_group,
                network_resource_group=args.network_resource_group,
                storage_resource_group=args.storage_resource_group,
                network=args.azure_network, subnet=args.azure_subnet,
                no_connection_test=args.skip_check,
                skip_load_defaults=args.skip_load_defaults,
                endpoint_base_url=args.azure_endpoint_base_url,
                storage_suffix=args.azure_storage_suffix,
                storage_account=args.storage_account,
                private_range=args.cluster_range,
            )
        else:
            if args.from_environment:
                if not all([args.resource_group, args.location, args.azure_network, args.azure_subnet]):
                    logger.error("Arguments azure-network, azure-subnet, location, and resource_group are required with environment")
                    parser.exit(1)
            else:
                if not all([args.application_id, args.application_secret, args.tenant_id]):
                    logger.error("Arguments tenant-id, application-id, and application-secret are required")
                    parser.exit(1)

                    if not args.subscription_id:
                        subscriptions = Service._list_subscriptions(
                            application_id=args.application_id,
                            application_secret=args.application_secret,
                            tenant_id=args.tenant_id)
                        args.subscription_id = subscriptions[0]['subscriptionId']

                if not all([args.subscription_id, args.azure_network, args.azure_subnet, args.resource_group, args.location]):
                    logger.error("Arguments subscription-id, azure-network, azure-subnet, resource-group, and location are required")
                    parser.exit(1)


                # set these env vars based on the credentials passed into vfxt.py
                # DefaultAzureCredential will use them to create an EnvironmentCredential
                os.environ['AZURE_TENANT_ID'] = args.tenant_id
                os.environ['AZURE_CLIENT_ID'] = args.application_id
                os.environ['AZURE_CLIENT_SECRET'] = args.application_secret

            opts = {
                'subscription_id': args.subscription_id,
                'application_id': args.application_id,
                'application_secret': args.application_secret,
                'tenant_id': args.tenant_id,
                'resource_group': args.resource_group,
                'network_resource_group': args.network_resource_group,
                'storage_account': args.storage_account,
                'storage_resource_group': args.storage_resource_group,
                'location': args.location,
                'network': args.azure_network,
                'subnet': args.azure_subnet,
                'zone': args.azure_zones,
                'proxy_uri': args.proxy_uri,
                'private_range': args.cluster_range,
                'no_connection_test': args.skip_check,
                'skip_load_defaults': args.skip_load_defaults,
                'endpoint_base_url': args.azure_endpoint_base_url,
                'storage_suffix': args.azure_storage_suffix,
            }
            if args.from_environment:
                service = Service.environment_init(**opts)
            else:
                service = Service(**opts)

        service._get_user_shelveable = _get_user_shelveable_azure

        if args.ssh_key:
            try:
                with open(args.ssh_key) as f:
                    ssh_key_data = f.read()
                    if 'rsa' not in ssh_key_data:
                        raise Exception("The SSH key must be of type RSA")
                    args.ssh_key = ssh_key_data
            except Exception as e:
                logger.error("Failed to read SSH key: {}".format(e))
                parser.exit(1)

        if args.create and (not (args.no_corefiler or args.nfs_mount) and not args.storage_account):
            logger.error("You must specify a storage account for cloud corefilers")
            parser.exit(1)

        if args.add_nodes:
            if args.nodes > 3:
                logger.error("Adding more than 3 cluster nodes is not supported")
                parser.exit(1)

        # off for Azure unless requested
        args.disable_bucket_encryption = True
        if args.enable_bucket_encryption:
            args.disable_bucket_encryption = False

        if args.ultra_ssd:
            args.data_disk_type = 'UltraSSD_LRS'

        if args.azure_tag:
            args.azure_tag = {n.split(':')[0]: (n.split(':')[1] or '') for n in args.azure_tag if len(n.split(':')) > 1}

    # generic service options
    service.POLLTIME = args.poll_time

    if args.node_cache_size:
        if any([args.data_disk_count, args.data_disk_size]):
            logger.warning("Overriding --data-disk-count and --data-disk-size with --node-cache-size")
        disk_config = service._cache_to_disk_config(args.node_cache_size, disk_type=args.data_disk_type, machine_type=args.instance_type)
        args.data_disk_count = disk_config[0]
        args.data_disk_size = disk_config[1]
        logger.debug("Cache size {} specified, setting disk count and size to {}, {}".format(args.node_cache_size, args.data_disk_count, args.data_disk_size))

    if args.create:
        # run a service check first
        try:
            if not args.skip_check:
                service.check()
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error(e)
            parser.exit(1)

        if not args.no_corefiler:
            if not args.disable_bucket_encryption and not args.core_filer_key_file:
                err_msg = 'Container/bucket encryption has been specified but a corefiler key file path was not supplied. To use container/bucket encryption you need to also specify a file path using --core-filer-key-file into which the generated key will be saved.'
                logger.error(err_msg)
                parser.exit(1)

        # minimum args for create
        if not all([args.instance_type, args.cluster_name, args.admin_password]):
            logger.error("Arguments instance-type, cluster-name, and admin-password are required")
            parser.exit(1)
        if args.nodes and args.nodes < 3: # we default below if nothing was specified
            logger.error("Cluster sizes below 3 are not supported")
            parser.exit(1)
        if args.nodes and args.nodes > 24:
            logger.error("Cluster sizes above 24 are not supported")
            parser.exit(1)
        # cluster create options
        options = {
            'size': args.nodes or 3,
            'data_disk_count': args.data_disk_count,
            'data_disk_size': args.data_disk_size,
            'data_disk_type': args.data_disk_type,
            'data_disk_iops': args.data_disk_iops,
            'data_disk_mbps': args.data_disk_mbps,
            'root_image': args.image_id,
            'root_size': args.root_size,
            'wait_for_state': args.wait_for_state,
            'wait_for_state_duration': args.wait_for_state_duration,
            'network_security_group': args.network_security_group,
            'config_expiration': args.configuration_expiration,
            'tags': args.azure_tag,
            'skip_cleanup': args.skip_cleanup,
            'skip_node_renaming': args.skip_node_renaming,
            'proxy_uri': args.cluster_proxy_uri,
            'auto_public_address': args.public_address,
            'management_address': args.management_address,
            'address_range_start': args.cluster_address_range_start,
            'address_range_end': args.cluster_address_range_end,
            'address_range_netmask': args.cluster_address_range_netmask,
            'instance_addresses': args.azure_instance_addresses,
            'trace_level': args.trace_level,
            'timezone': args.timezone,
            'admin_ssh_data': args.ssh_key, # azure ssh key
            'azure_role': args.azure_role,
            'azure_identity': args.azure_identity,
            'join_wait': args.join_wait or None,
            'enable_boot_diagnostics': args.enable_boot_diagnostics,
            'root_disk_caching': args.root_disk_caching,
            'data_disk_caching': args.data_disk_caching,
            'proximity_placement_group': args.proximity_placement_group
        }
        # prune out unfortunate command line defaults
        options = {k: v for k, v in viewitems(options) if v is not None and v != ''}

        logger.info("Creating {} cluster {}".format(args.instance_type, args.cluster_name))
        try:
            cluster = Cluster.create(service, args.instance_type, args.cluster_name, args.admin_password, **options)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error(e)
            logger.error("Failed to create cluster")
            parser.exit(1)

        corefiler_name = None
        if not args.no_corefiler:
            try:
                if args.nfs_mount:
                    corefiler_name = _add_nfs_corefiler(cluster, logger, args)
                else:
                    corefiler_name = _add_bucket_corefiler(cluster, logger, args)
            except (KeyboardInterrupt, Exception) as e:
                if args.debug:
                    logger.exception(e)
                logger.error(e)
                if not args.skip_cleanup:
                    cluster.destroy(quick_destroy=True)
                logger.error("Failed to configure core filer")
                parser.exit(1)

        if not args.no_vserver:
            try:
                logger.info("Creating vserver {}".format(args.vserver))
                vserver_opts = {
                    'netmask': args.vserver_address_range_netmask,
                    'start_address': args.vserver_address_range_start,
                    'end_address': args.vserver_address_range_end,
                    'home_addresses': args.vserver_home_addresses,
                }
                cluster.add_vserver(args.vserver, **vserver_opts)
                if corefiler_name:
                    logger.info("Creating vserver junction {}".format(corefiler_name))
                    junction_opts = {
                        'path': args.junction
                    }
                    if args.nfs_mount:
                        mount = args.nfs_mount.split(':')[-1]
                        junction_opts['path'] = args.junction or '/{}'.format(corefiler_name)
                        junction_opts['export'] = mount
                        junction_opts['subdir'] = args.subdir
                    cluster.add_vserver_junction(args.vserver, corefiler_name, **junction_opts)
            except (KeyboardInterrupt, Exception) as e:
                if args.debug:
                    logger.exception(e)
                logger.error(e)
                if not args.skip_cleanup:
                    cluster.destroy(quick_destroy=True)
                logger.error("Failed to configure vserver")
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
            cluster.mgmt_ip = args.management_address
            cluster.admin_password = args.admin_password
            if args.wait_for_state:
                cluster.wait_for_healthcheck(state=args.wait_for_state, conn_retries=20, duration=args.wait_for_state_duration)
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

        node_names = ' '.join([i.id() for i in cluster.nodes])
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
            cluster.mgmt_ip = args.management_address
            cluster.admin_password = args.admin_password
            if args.wait_for_state:
                cluster.wait_for_healthcheck(state=args.wait_for_state, conn_retries=20, duration=args.wait_for_state_duration)

        logger.info("Completed unshelving nodes {}".format(node_names))

    elif args.add_nodes:
        if not all([args.nodes, args.management_address, args.admin_password]):
            logger.error("Arguments nodes, management-address, and admin-password are required")
            parser.exit(1)
        cluster = _get_cluster(service, logger, args)
        if not cluster:
            logger.error("Cluster not found.")
            parser.exit(1)
        if args.nodes + len(cluster.nodes) > 24:
            logger.error("Cluster sizes above 24 are not supported")
            parser.exit(1)

        options = {
            'root_image': args.image_id,
            'root_size': args.root_size,
            'data_disk_count': args.data_disk_count,
            'data_disk_size': args.data_disk_size,
            'data_disk_type': args.data_disk_type,
            'data_disk_iops': args.data_disk_iops,
            'data_disk_mbps': args.data_disk_mbps,
            'tags': args.azure_tag,
            'skip_cleanup': args.skip_cleanup,
            'skip_node_renaming': args.skip_node_renaming,
            'machine_type': args.instance_type,
            'auto_public_address': args.public_address,
            'join_wait': args.join_wait or None,
            'home_addresses': args.vserver_home_addresses,
            'admin_ssh_data': args.ssh_key, # azure ssh key
            'azure_role': args.azure_role,
            'azure_identity': args.azure_identity,
            'zone': args.azure_zones,
        }
        # prune out unfortunate command line defaults
        options = {k: v for k, v in viewitems(options) if v is not None and v != ''}

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
            if 'A directory manager rebalance operation is already scheduled' in str(e):
                parser.exit(1)
        if args.wait_for_state:
            cluster.wait_for_healthcheck(state=args.wait_for_state, duration=args.wait_for_state_duration)
        logger.info("Complete")

    elif args.interact:
        from vFXT.serviceInstance import ServiceInstance # handy import #pylint: disable=unused-variable,possibly-unused-variable
        local = globals()
        local.update(locals())
        banner = "\n--- Service object available as 'service' ---\n"
        try:
            from IPython import start_ipython
            logger.info(banner)
            start_ipython(argv=['--classic', '--no-banner'], user_ns=local)
        except ImportError:
            from code import interact
            interact(local=local, banner=banner)

    elif args.upgrade_alternate_image:
        if not args.upgrade_url:
            logger.error("Provide a URL from which to upgrade")
            parser.exit(1)
        cluster = _get_cluster(service, logger, args)
        try:
            cluster.upgrade_alternate_image(args.upgrade_url)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to upgrade alternate image: {}".format(e))
            parser.exit(1)

    elif args.activate_alternate_image:
        cluster = _get_cluster(service, logger, args)
        try:
            cluster.activate_alternate_image(ha=not args.upgrade_non_ha)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to activate alternate image: {}".format(e))
            parser.exit(1)

    elif args.upgrade:
        if not args.upgrade_url:
            logger.error("Provide a URL from which to upgrade")
            parser.exit(1)
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)
        try:
            cluster.upgrade(args.upgrade_url, ha=not args.upgrade_non_ha)
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to upgrade cluster: {}".format(e))
            parser.exit(1)
        if args.wait_for_state:
            cluster.wait_for_healthcheck(state=args.wait_for_state, duration=args.wait_for_state_duration)

    elif args.check:
        logger.info("Performing quota checks...")
        opts = {
            'instances': args.nodes,
            'machine_type': args.instance_type,
            'data_disk_type': args.data_disk_type,
            'data_disk_size': args.data_disk_size,
            'data_disk_count': args.data_disk_count
        }
        service.check(**opts)
        logger.info("Complete")
    elif args.telemetry:
        if not all([args.management_address, args.admin_password]):
            logger.error("Arguments management-address and admin-password are required")
            parser.exit(1)
        cluster = _get_cluster(service, logger, args)
        if not cluster or not cluster.nodes:
            logger.error("Cluster not found.")
            parser.exit(1)
        try:
            cluster.telemetry(wait=True, mode=args.telemetry_mode)
            logger.info("Complete")
        except Exception as e:
            if args.debug:
                logger.exception(e)
            logger.error("Failed to kick off telemetry: {}".format(e))
            parser.exit(1)
    else:
        parser.print_help()
        parser.exit(1)


if __name__ == '__main__':
    try:
        old_py_e = Exception("vFXT requires 2.7.10 or later")
        if sys.version_info.major < 2:
            raise Exception("vFXT requires 2.7.10 or later")
        if sys.version_info.major == 2 and (sys.version_info.minor < 7 or sys.version_info.micro < 10):
            raise Exception("vFXT requires 2.7.10 or later")
        if not hasattr(ssl, 'PROTOCOL_TLSv1_2'):
            raise Exception("vFXT requires OpenSSL with TLSv1.2 support")
        if not hasattr(ssl, 'OPENSSL_VERSION_INFO') or ssl.OPENSSL_VERSION_INFO < (1, 0, 1, 7): # at least OpenSSL 1.0.1
            raise Exception("vFXT requires OpenSSL version 1.0.1 or later")
    except Exception as e:
        logging.error(e)
        sys.exit(-1)

    main()
