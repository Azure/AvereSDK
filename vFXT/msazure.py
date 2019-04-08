# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
'''Abstraction for doing things on the instances via MS Azure

Cookbook/examples:

service = vFXT.msazure.Service(
    subscription_id=subscription_id,
    application_id=application_id,
    application_secret=application_secret,
    tenant_id=tenant_id,
    resource_group=resource_group,
    location=location,
    network=azure_network,
    subnet=azure_subnet,
    # for diagnostics
    storage_account=storage_account,
)

# Connection factory
connection = msazure.connection()

instances = msazure.find_instances()
instances = msazure.get_instances([])

instance = msazure.get_instance('instance id')
msazure.start(instance)
msazure.stop(instance)
msazure.restart(instance)
msazure.destroy(instance)

msazure.shelve(instance)
msazure.unshelve(instance)

instance = msazure.refresh(instance)

print msazure.name(instance)
print msazure.ip(instance)
print msazure.fqdn(instance)
print msazure.status(instance)

if msazure.is_on(instance): pass
if msazure.is_off(instance): pass
if msazure.is_shelved(instance): pass

msazure.wait_for_status(instance, msazure.ON_STATUS, msazure.WAIT_FOR_SUCCESS)

msazure.create_instance(machine_type, name, boot_disk_image, other_disks=None, **options)
msazure.create_cluster(self, cluster, **options)

msazure.create_container(name)
msazure.delete_container(name)

msazure.load_cluster_information(cluster)

ip_count = 12
ip_addresses, mask = msazure.get_available_addresses(count=ip_count, contiguous=True)
msazure.get_dns_servers()
msazure.get_ntp_servers()
msazure.get_default_router()

serializeme = msazure.export()
newmsazure = vFXT.msazure.Service(**serializeme)

'''
import time
import threading
import Queue
import logging
import urlparse
import httplib
import json
import uuid
import re
from itertools import cycle

# silence the azure sdk
logging.getLogger('msrest.http_logger').setLevel(logging.ERROR)
logging.getLogger('msrest.pipeline').setLevel(logging.ERROR)
logging.getLogger('msrest.service_client').setLevel(logging.ERROR)
logging.getLogger('adal-python').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger('cli.azure.cli.core').setLevel(logging.ERROR)
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('requests_oauthlib.oauth2_session').setLevel(logging.CRITICAL)
logging.getLogger('msrestazure.azure_active_directory').setLevel(logging.CRITICAL)
logging.getLogger('keyring.backend').setLevel(logging.CRITICAL)

import azure.storage.blob
import azure.storage.common
import azure.common.client_factory
import azure.common.credentials
import azure.mgmt.authorization
import azure.mgmt.compute
import azure.mgmt.network
import azure.mgmt.storage
import azure.mgmt.resource
import azure.mgmt.msi
import msrestazure.azure_active_directory
import msrestazure.azure_cloud

# silence requests
import requests
requests.packages.urllib3.disable_warnings() # pylint: disable=no-member

from vFXT.cidr import Cidr
from vFXT.serviceInstance import ServiceInstance
from vFXT.service import *

log = logging.getLogger(__name__)

class ContainerExistsException(Exception): pass

class Service(ServiceBase):
    '''Azure service backend'''
    ON_STATUS=['ProvisioningState/succeeded','PowerState/running']
    OFF_STATUS=['ProvisioningState/succeeded','PowerState/deallocated']
    STOP_STATUS=['ProvisioningState/succeeded','PowerState/stopped']
    #DESTROYED_STATUS=['ProvisioningState/succeeded']
    NTP_SERVERS=['time.windows.com']
    DNS_SERVERS=['168.63.129.16']
    MACHINE_DEFAULTS={
        'Standard_A4':      {'data_disk_size': 128,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_A7':      {'data_disk_size': 128,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_A8':      {'data_disk_size': 128,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_A9':      {'data_disk_size': 128,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_A10':     {'data_disk_size': 128,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_A11':     {'data_disk_size': 128,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_D4':      {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_D4_v2':   {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_D5_v2':   {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_D13':     {'data_disk_size': 512,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 4},
        'Standard_D13_v2':  {'data_disk_size': 512,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 4},
        'Standard_D14':     {'data_disk_size': 512,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 4},
        'Standard_D14_v2':  {'data_disk_size': 512,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 4},
        'Standard_DS1':     {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_DS4':     {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_DS4_v2':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_DS5_v2':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_D2s_v3':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_D4s_v3':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 0, 'max_data_disk_count': 8},
        'Standard_D8s_v3':  {'data_disk_size': 256,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 16},
        'Standard_D16s_v3': {'data_disk_size': 256,'data_disk_count': 4, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_D32s_v3': {'data_disk_size': 512,'data_disk_count': 8, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_D64s_v3': {'data_disk_size': 512,'data_disk_count': 8, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_DS13':    {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_DS13_v2': {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_DS14':    {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 64},
        'Standard_DS14_v2': {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 64},
        'Standard_DS15_v2': {'data_disk_size': 512,'data_disk_count': 8, 'node_count': 3, 'max_data_disk_count': 64},
        'Standard_E2s_v3':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 4},
        'Standard_E4s_v3':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 8},
        'Standard_E8s_v3':  {'data_disk_size': 256,'data_disk_count': 1, 'node_count': 3, 'max_data_disk_count': 16},
        'Standard_E16s_v3': {'data_disk_size': 256,'data_disk_count': 4, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_E32s_v3': {'data_disk_size': 512,'data_disk_count': 8, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_E64s_v3': {'data_disk_size': 512,'data_disk_count': 8, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_E64is_v3':{'data_disk_size': 512,'data_disk_count': 8, 'node_count': 3, 'max_data_disk_count': 32},
        'Standard_G3':      {'data_disk_size': 512,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_G4':      {'data_disk_size': 512,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_G5':      {'data_disk_size': 512,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_GS3':     {'data_disk_size': 512,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_GS4':     {'data_disk_size': 512,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 4},
        'Standard_GS5':     {'data_disk_size': 512,'data_disk_count': 2, 'node_count': 0, 'max_data_disk_count': 4},
    }
    # managed also supports 32 and 64
    # 256 mentioned here: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/managed-disks-overview
    VALID_DATA_DISK_SIZES = [128, 256, 512, 1024, 2048, 4095]
    MACHINE_TYPES = MACHINE_DEFAULTS.keys()
    BLOB_HOST = 'blob.core.windows.net'
    BLOB_URL_FMT = 'https://{}.{}/{}/{}' # account, host, container, blob
    DEFAULT_STORAGE_ACCOUNT_TYPE = 'Premium_LRS'
    AZURE_INSTANCE_HOST = '169.254.169.254'
    AZURE_ENDPOINT_HOST = 'management.azure.com'
    INSTANCENAME_RE = re.compile(r'[a-zA-Z][-a-z0-9A-Z_]*$')
    CONTAINER_NAME_RE = re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9]*$')
    SYSTEM_CONTAINER = 'system'
    ENDPOINT_TEST_HOSTS = ['management.azure.com']
    ROLE_PERMISSIONS = [{
        'notActions': [],
        'actions': [
            'Microsoft.Compute/virtualMachines/read',
            'Microsoft.Network/networkInterfaces/read',
            'Microsoft.Network/networkInterfaces/write',
            'Microsoft.Network/virtualNetworks/subnets/read',
            'Microsoft.Network/virtualNetworks/subnets/join/action',
            'Microsoft.Resources/subscriptions/resourceGroups/read',
            'Microsoft.Storage/storageAccounts/blobServices/containers/delete',
            'Microsoft.Storage/storageAccounts/blobServices/containers/read',
            'Microsoft.Storage/storageAccounts/blobServices/containers/write',
        ],
        'data_actions': [
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete',
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read',
            'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write',
        ],
    }]
    WAIT_FOR_SUCCESS = 2400 # override ServiceBase.WAIT_FOR_SUCCESS
    WAIT_FOR_START = 2400 # override ServiceBase.WAIT_FOR_START
    WAIT_FOR_STOP = 2400 # override ServiceBase.WAIT_FOR_STOP
    WAIT_FOR_DESTROY = 2400 # override ServiceBase.WAIT_FOR_DESTROY
    NEW_ROLE_FETCH_RETRY = 120
    OFFLINE_DEFAULTS = {
        'version': '1',
        'clustermanager': {
            'maxNumNodes': 20,
            'cacheSizes': [
                { 'size': 256, 'type': None, 'label': '250' },
                { 'size': 1024, 'type': None, 'label': '1000' },
                { 'size': 4096, 'type': None, 'label': '4000' },
                { 'size': 8192, 'type': None, 'label': '8000' }
            ],
            'inst': '',
            'pkg': '',
            'instanceTypes': [ 'Standard_D16s_v3', 'Standard_E32s_v3' ]
        }
    }
    DNS_TIMEOUT = 10.0
    COREFILER_TYPE = 'azure'
    COREFILER_CRED_TYPE = 'azure-storage'
    COREFILER_CRED_MSI = 'azure-msi-s'
    DEFAULT_CACHING_OPTION = 'None'
    VALID_CACHING_OPTIONS = ['ReadOnly', 'ReadWrite', 'None']
    METADATA_FETCH_RETRIES = 5
    ENDPOINT_FETCH_RETRIES = 2
    TOKEN_RESOURCE = 'https://management.azure.com/'
    AUTO_LICENSE = True
    WAIT_FOR_NIC = 180
    WAIT_FOR_IPCONFIG = 300
    REGIONS_WITH_3_FAULT_DOMAINS = ['canadacentral', 'centralus', 'eastus', 'eastus2', 'northcentralus', 'northeurope', 'southcentralus', 'westeurope', 'westus']
    MAX_UPDATE_DOMAIN_COUNT = 20
    ALLOCATE_INSTANCE_ADDRESSES = True
    DEFAULT_MARKETPLACE_URN = 'microsoft-avere:vfxt:avere-vfxt-node:latest'
    NIC_OPERATIONS_RETRY = 60
    AZURE_ENVIRONMENTS = {
        'AzureUSGovernment': { 'endpoint': msrestazure.azure_cloud.AZURE_US_GOV_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_US_GOV_CLOUD.suffixes.storage_endpoint},
        'AzureCloud':        { 'endpoint': msrestazure.azure_cloud.AZURE_PUBLIC_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_PUBLIC_CLOUD.suffixes.storage_endpoint},
        'AzureChinaCloud':   { 'endpoint': msrestazure.azure_cloud.AZURE_CHINA_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_CHINA_CLOUD.suffixes.storage_endpoint},
        'AzureGermanCloud':  { 'endpoint': msrestazure.azure_cloud.AZURE_GERMAN_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_GERMAN_CLOUD.suffixes.storage_endpoint},
        # compat map
        'AZUREUSGOVERNMENTCLOUD': { 'endpoint': msrestazure.azure_cloud.AZURE_US_GOV_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_US_GOV_CLOUD.suffixes.storage_endpoint},
        'AZUREPUBLICCLOUD':       { 'endpoint': msrestazure.azure_cloud.AZURE_PUBLIC_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_PUBLIC_CLOUD.suffixes.storage_endpoint},
        'AZURECHINACLOUD':        { 'endpoint': msrestazure.azure_cloud.AZURE_CHINA_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_CHINA_CLOUD.suffixes.storage_endpoint},
        'AZUREGERMANCLOUD':       { 'endpoint': msrestazure.azure_cloud.AZURE_GERMAN_CLOUD.endpoints.resource_manager, 'storage_suffix': msrestazure.azure_cloud.AZURE_GERMAN_CLOUD.suffixes.storage_endpoint},
    }
    REGION_FIXUP = {
        "centralindia": "indiacentral",
        "southindia": "indiasouth",
        "westindia": "indiawest",
    }

    def __init__(self, subscription_id=None, application_id=None, application_secret=None,
                       tenant_id=None, resource_group=None, storage_account=None,
                       **options):
        '''Constructor

            Arguments:
                subscription_id (str): Azure subscription identifier
                application_id (str): AD application ID
                application_secret (str): AD application secret
                tenant_id (str): AD application tenant identifier
                resource_group (str): Resource group
                storage_account (str): Azure Storage account
                storage_resource_group (str, optional): Azure Storage account resource group (if different from the instance resource_group)
                access_token (str, optional): Azure access token

                location (str, optional): Azure location
                network (str, optional): Azure virtual network
                subnet ([str], optional): list of Azure virtual network subnets

                network_resource_group (str, optional): Network resource group (if different from instance resource_group)
                network_security_group (str, optional): network security group name
                private_range (str, optional): private address range (cidr)
                proxy_uri (str, optional): URI of proxy resource (e.g. http://user:pass@172.16.16.20:8080)
                no_connection_test (bool, optional): skip connection test

                endpoint_base_url (str, optional): A custom endpoint URL
                storage_suffix (str, optional): The blob storage service suffix (if not blob.core.windows.net)

            If an access token is provided it is used in place of the application ID/secret pair
            for API authentication.
        '''
        super(Service, self).__init__()
        self.subscription_id = subscription_id
        self.application_id     = application_id
        self.application_secret = application_secret
        self.tenant_id       = tenant_id
        self.resource_group  = resource_group
        self.storage_account = storage_account
        self.on_instance     = options.get('on_instance') or False
        self.access_token    = options.get('access_token') or None

        self.location        = options.get('location') or None
        self.network         = options.get('network') or None
        self.subnets         = options.get('subnet') or []
        self.subnets         = [self.subnets] if isinstance(self.subnets, basestring) else self.subnets
        self.private_range   = options.get('private_range') or None
        self.source_address  = options.get('source_address') or None
        self.endpoint_base_url = options.get('endpoint_base_url') or None
        self.storage_suffix = options.get('storage_suffix') or None

        self.proxy_uri       = options.get('proxy_uri') or None
        if self.proxy_uri:
            self.set_proxy(self.proxy_uri)

        self.use_environment_for_auth = options.get('use_environment_for_auth') or False

        self.network_resource_group = options.get('network_resource_group') or self.resource_group
        self.network_security_group = options.get('network_security_group') or None

        self.storage_resource_group = options.get('storage_resource_group') or self.resource_group

        if not self.use_environment_for_auth:
            if not any([self.access_token, self.application_id]):
                raise vFXTConfigurationException("You must provide an access token or an application id/secret pair")

        # should have a resource group at least
        if not self.resource_group:
            raise vFXTConfigurationException("You must provide the resource group name")

        log.debug("Using azure.mgmt.authorization version {}".format(azure.mgmt.authorization.version.VERSION))
        log.debug("Using azure.mgmt.compute version {}".format(azure.mgmt.compute.version.VERSION))
        log.debug("Using azure.mgmt.network version {}".format(azure.mgmt.network.version.VERSION))
        log.debug("Using azure.mgmt.storage version {}".format(azure.mgmt.storage.version.VERSION))
        log.debug("Using azure.mgmt.resource version {}".format(azure.mgmt.resource.version.VERSION))

        if not options.get('no_connection_test', None):
            self.connection_test()

    def connection_test(self):
        '''Connection test

            Raises: vFXTConfigurationException
        '''
        log.debug("Performing connection test")

        try:
            if not self.proxy: # proxy environments may block outgoing name resolution
                self.dns_check(self.DNS_TIMEOUT)
            self.connection()
        except Exception as e:
            raise vFXTServiceConnectionFailure("Failed to establish connection to service: {}".format(e))

        return True

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
        if self.location:
            try:
                for q in self.connection('network').usages.list(self.location):
                    if q.limit == 0: continue
                    if q.current_value/q.limit > percentage:
                        log.warn("QUOTA ALERT: Using {} of {} {}".format(q.current_value, q.limit, q.name.localized_value))
                    else:
                        log.debug("Using {} of {} {}".format(q.current_value, q.limit, q.name.localized_value))
            except Exception as e:
                log.debug(e)
            try:
                for q in self.connection().usage.list(self.location):
                    if q.limit == 0: continue
                    if q.current_value/q.limit > percentage:
                        log.warn("QUOTA ALERT: Using {} of {} {}".format(q.current_value, q.limit, q.name.localized_value))
                    else:
                        log.debug("Using {} of {} {}".format(q.current_value, q.limit, q.name.localized_value))
            except Exception as e:
                log.debug(e)
        try:
            for q in self.connection('storage').usage.list():
                if q.limit == 0: continue
                if q.current_value/q.limit > percentage:
                    log.warn("QUOTA ALERT: Using {} of {} {}".format(q.current_value, q.limit, q.name.localized_value))
                else:
                    log.debug("Using {} of {} {}".format(q.current_value, q.limit, q.name.localized_value))
        except Exception as e:
            log.debug(e)

    def connection(self, connection_type='compute', **options):
        '''Connection factory, returns a new connection or thread local copy

            Arguments:
                connection_type (str, optional): connection type (compute, storage)
                **options (optional)


            Connection types include:
                authorization
                blobstorage
                compute (default)
                identity
                network
                resource
                storage
                subscription

            blobstorage can take optional arguments
                storage_account (str, optional): defaults to self.storage_account
                resource_group (str, optional): defaults to self.storage_resource_group
        '''
        # bookkeeping
        if not hasattr(self.local, 'connections'):
            self.local.connections = {}

        if self.on_instance and hasattr(self.local, 'instance_data'):
            try:
                if int(self.local.instance_data['access_token']['expires_on']) < int(time.time()):
                    log.debug("Access token expired, forcing refresh")
                    self.local.connections = {}
                    del self.local.instance_data
            except Exception as e:
                log.debug(e)

        connection_types = {
            'authorization': {'cls': azure.mgmt.authorization.AuthorizationManagementClient, 'pass_subscription': True},
            'blobstorage': None, # special handling below
            'compute': {'cls': azure.mgmt.compute.ComputeManagementClient, 'pass_subscription': True},
            'identity': {'cls': azure.mgmt.msi.ManagedServiceIdentityClient, 'pass_subscription': True},
            'network': {'cls': azure.mgmt.network.NetworkManagementClient, 'pass_subscription': True},
            'resource': {'cls': azure.mgmt.resource.ResourceManagementClient, 'pass_subscription': True},
            'storage': {'cls': azure.mgmt.storage.StorageManagementClient, 'pass_subscription': True},
            'subscription': {'cls': azure.mgmt.resource.SubscriptionClient, 'pass_subscription': False},
        }
        proxies = {'http': self.proxy_uri, 'https': self.proxy_uri} if self.proxy_uri else {}

        # if we do not already have a cached connection, make one
        if not self.local.connections.get(connection_type, False):
            newconn = None

            if connection_type not in connection_types:
                raise vFXTConfigurationException("Unknown connection type: {}".format(connection_type))
            if self.on_instance and not hasattr(self.local, 'instance_data'):
                self.local.instance_data = self.get_instance_data(source_address=self.source_address)
            log.debug("Creating connection of type {}".format(connection_type))

            # blobstorage connections are just returned (not cached) since they are tied to a storage account
            # and less frequently used
            if connection_type == 'blobstorage':
                storage_account = options.get('storage_account') or self.storage_account
                resource_group = options.get('resource_group') or self.storage_resource_group
                auth = {}
                if self.on_instance: # use MSI for auth
                    auth['token_credential'] = msrestazure.azure_active_directory.MSIAuthentication(resource='https://storage.azure.com/')
                else:
                    try:
                        keys = self.connection('storage').storage_accounts.list_keys(resource_group, storage_account).keys
                        if not keys:
                            raise Exception()
                    except Exception:
                        raise vFXTConfigurationException("Unable to look up storage keys for {}".format(storage_account))
                    auth['account_key'] = keys[0].value # just use the first one, may be multiple
                if self.storage_suffix:
                    auth['endpoint_suffix'] = self.storage_suffix
                return azure.storage.blob.blockblobservice.BlockBlobService(storage_account, **auth)

            connection_settings = connection_types[connection_type]
            connection_cls = connection_settings['cls']
            if self.use_environment_for_auth:
                # get_client_from_cli_profile seems racy, retry a few times
                retries = 3
                while True:
                    try:
                        newconn = azure.common.client_factory.get_client_from_cli_profile(connection_cls)
                        break
                    except Exception as e:
                        if log.isEnabledFor(logging.DEBUG):
                            log.exception(e)
                        retries -= 1
                        if retries == 0:
                            raise
            else:
                cloud_environment = msrestazure.azure_cloud.get_cloud_from_metadata_endpoint(self.endpoint_base_url) if self.endpoint_base_url else None
                if self.on_instance:
                    if cloud_environment:
                        creds = msrestazure.azure_active_directory.AADTokenCredentials(self.local.instance_data['access_token'], cloud_environment=cloud_environment)
                    else:
                        creds = msrestazure.azure_active_directory.AADTokenCredentials(self.local.instance_data['access_token'])
                else:
                    if cloud_environment:
                        creds = azure.common.credentials.ServicePrincipalCredentials(self.application_id, self.application_secret, tenant=self.tenant_id, cloud_environment=cloud_environment)
                    else:
                        creds = azure.common.credentials.ServicePrincipalCredentials(self.application_id, self.application_secret, tenant=self.tenant_id)

                connection_args = {}
                if options.get('api_version'):
                    connection_args['api_version'] = options.get('api_version')
                if self.endpoint_base_url:
                    connection_args['base_url'] = self.endpoint_base_url
                if connection_settings['pass_subscription']:
                    connection_args['subscription_id'] = self.subscription_id

                newconn = connection_cls(creds, **connection_args)
            # Add our proxy configuration, we do it here so we can support all cred types.
            # Some cred types support passing proxies, but some credential factories do
            # not support that mechanism
            for proto, url in proxies.items():
                newconn.config.proxies.add(proto, url)
            # save it off
            self.local.connections[connection_type] = newconn

        return self.local.connections[connection_type]

    @classmethod
    def get_instance_data(cls, **options):
        '''Detect the instance data

            Arguments:
                source_address (str, optional): source address for data request
                token_resource (str, optional): resource scope for returned token
                                       defaults to management, ie: 'http://management.azure.com/'
                                       other values include storage, 'https://storage.azure.com/'

            This only works when running on an Azure instance.

            This is a service specific data structure.

            Well known keys that can be expected across services:
            machine_type (str): machine/instance type
            account_id (str): account identifier
            service_id (str): unique identifier for this host
            ssh_keys ([str]): ssh keys
            cluster_cfg (str): cluster configuration
        '''
        source_address = options.get('source_address') or None
        token_resource = options.get('token_resource')
        instance_data = {}
        try:
            if source_address:
                source_address = (source_address, 0)
            connection_host = cls.AZURE_INSTANCE_HOST
            connection_port = httplib.HTTP_PORT
            headers = {'Metadata': 'true'}
            conn = httplib.HTTPConnection(connection_host, connection_port, source_address=source_address, timeout=CONNECTION_TIMEOUT)

            instance_data = {}

            # instance metadata
            attempts = 0
            while True:
                try:
                    url_path = '/metadata/instance?api-version=2018-10-01'
                    conn.request('GET', '{}'.format(url_path), headers=headers)
                    response = conn.getresponse()
                    if response.status == 200:
                        instance_data = json.loads(response.read())
                        break
                    raise vFXTServiceFailure("Failed to fetch instance data: {}".format(response.reason))
                except Exception as e:
                    log.debug(e)
                    attempts += 1
                    if attempts == cls.METADATA_FETCH_RETRIES:
                        raise
                    time.sleep(backoff(attempts))
                    # reconnect on failure
                    conn = httplib.HTTPConnection(connection_host, connection_port, source_address=source_address, timeout=CONNECTION_TIMEOUT)

            instance_location = instance_data['compute']['location'].lower() # region may be mixed case
            instance_location = cls.REGION_FIXUP.get(instance_location) or instance_location # region may be transposed

            if instance_data['compute']['azEnvironment'] in cls.AZURE_ENVIRONMENTS:
                instance_data['token_resource'] = cls.AZURE_ENVIRONMENTS.get(instance_data['compute']['azEnvironment']).get('endpoint')
            else:
                # must lookup endpoint metadata based on the VM location
                attempts = 0
                endpoint_conn = httplib.HTTPSConnection(cls.AZURE_ENDPOINT_HOST, source_address=source_address, timeout=CONNECTION_TIMEOUT)
                while True:
                    try:
                        endpoint_conn.request('GET', '/metadata/endpoints?api-version=2017-12-01')
                        response = endpoint_conn.getresponse()
                        if response.status == 200:
                            endpoint_data = json.loads(response.read())
                            for endpoint_name in endpoint_data['cloudEndpoint']:
                                endpoint = endpoint_data['cloudEndpoint'][endpoint_name]
                                if instance_location in [_.lower() for _ in endpoint['locations']]: # force lowercase comparison
                                    instance_data['token_resource'] = 'https://{}'.format(endpoint['endpoint']) # Always assume URL format
                            break
                        raise vFXTServiceFailure("Failed to fetch endpoint data: {}".format(response.reason))
                    except Exception as e:
                        log.debug(e)
                        attempts += 1
                        if attempts == cls.ENDPOINT_FETCH_RETRIES:
                            raise
                        time.sleep(backoff(attempts))
                        # reconnect on failure
                        endpoint_conn = httplib.HTTPSConnection(cls.AZURE_ENDPOINT_HOST, source_address=source_address, timeout=CONNECTION_TIMEOUT)

            # token metadata
            attempts = 0
            if not token_resource:
                token_resource = instance_data.get('token_resource') or cls.TOKEN_RESOURCE
            while True:
                try:
                    url_path = '/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}'.format(token_resource)
                    conn.request('GET', '{}'.format(url_path), headers=headers)
                    response = conn.getresponse()
                    if response.status == 200:
                        instance_data['access_token'] = json.loads(response.read())
                        break
                    # If MSI is not enabled, you get '400 Identity not found'.  We could
                    # conceivably set instance_data['access_token'] = None and return,
                    # but since we're requiring MSI now, we don't bother handling that case
                    # and throw the vFXTServiceFailure exception.
                    raise vFXTServiceFailure("Failed to fetch identity data: {}".format(response.reason))
                except Exception as e:
                    log.debug(e)
                    attempts += 1
                    if attempts == cls.METADATA_FETCH_RETRIES:
                        raise
                    time.sleep(backoff(attempts))
                    # reconnect on failure
                    conn = httplib.HTTPConnection(connection_host, connection_port, source_address=source_address, timeout=CONNECTION_TIMEOUT)

            instance_data['machine_type'] = instance_data['compute']['vmSize']
            instance_data['account_id'] = instance_data['compute']['subscriptionId']
            instance_data['service_id'] = instance_data['compute']['name']
            instance_data['hostname'] = instance_data['compute']['name']
            instance_data['ssh_keys'] = [_['keyData'].strip() for _ in instance_data['compute'].get('publicKeys', [])]
            instance_data['cluster_cfg'] = ''
        except Exception as e:
            log.exception(e)
            raise vFXTServiceMetaDataFailure("Not on an Azure instance")

        return instance_data

    @classmethod
    def on_instance_init(cls, **options):
        '''Init an Azure service object from instance metadata
            Arguments:
                source_address (str, optional): source address for data request
                proxy_uri (str, optional): URI of proxy resource
                no_connection_test (bool, optional): skip connection tests, defaults to False
                skip_load_defaults (bool, optional): do not fetch defaults
                resource_group (str, optional): Resource group
                network_resource_group (str, optional): Network resource group (if different from instance resource_group)
                storage_resource_group (str, optional): Azure Storage account resource group (if different from the instance resource_group)
                network (str, optional): Azure virtual network
                subnet (str, optional): Azure virtual network subnets

                endpoint_base_url (str, optional): passed to __init__
                storage_account (str, optional): passed to __init__
                storage_suffix (str, optional): passed to __init__
                private_range (str, optional): passed to __init__

            This is only meant to be called on instance.  Otherwise will
            raise a vFXTConfigurationException exception.
        '''
        source_address  = options.get('source_address') or None
        proxy_uri       = options.get('proxy_uri') or None
        no_connection_test = options.get('no_connection_test') or False
        skip_load_defaults = options.get('skip_load_defaults') or False

        network = options.get('network') or None
        subnet = options.get('subnet') or None
        resource_group = options.get('resource_group') or None
        network_resource_group = options.get('network_resource_group') or None
        storage_resource_group = options.get('storage_resource_group') or None

        instance_data = cls.get_instance_data(source_address=source_address, no_connection_test=no_connection_test)
        log.debug('Read instance data: {}'.format(instance_data))
        try:
            service = Service(source_address=source_address, proxy_uri=proxy_uri,
                              no_connection_test=no_connection_test,
                              subscription_id=str(instance_data['account_id']),
                              location=instance_data['compute']['location'],
                              resource_group=resource_group or instance_data['compute']['resourceGroupName'],
                              network_resource_group=network_resource_group,
                              storage_resource_group=storage_resource_group,
                              subnet=subnet, network=network,
                              access_token=instance_data.get('access_token'),
                              on_instance=True, skip_load_defaults=skip_load_defaults,
                              endpoint_base_url=options.get('endpoint_base_url') or instance_data.get('token_resource') or None,
                              storage_suffix=options.get('storage_suffix'),
                              storage_account=options.get('storage_account'),
                              private_range=options.get('private_range'),
            )
            service.local.instance_data = instance_data

            # detect our network/subnet by the instance NIC
            instance  = service.get_current_instance()
            if not instance:
                raise vFXTConfigurationException("Unable to retrieve current instance")

            nic_id    = instance.network_profile.network_interfaces[0].id
            nic_name  = nic_id.split('/')[-1]
            nic_rsg   = nic_id.split('/')[4]
            nic       = service.connection('network').network_interfaces.get(nic_rsg, nic_name)
            subnet_id = nic.ip_configurations[0].subnet.id

            if not subnet:
                service.subnets = [subnet_id.split('/')[-1]]
            if not network:
                service.network = subnet_id.split('/')[-3]
            if nic.network_security_group:
                service.network_security_group = nic.network_security_group.id.split('/')[-1]
            if not network_resource_group:
                service.network_resource_group = subnet_id.split('/')[4] # our subnet/network may be in different resource groups

            service.tenant_id = instance.identity.tenant_id

            return service
        except (vFXTServiceFailure, vFXTServiceConnectionFailure) as e:
            raise
        except Exception as e:
            log.exception("Failed on instance initialization: {}".format(e))
            raise vFXTConfigurationException(e)

    @classmethod
    def environment_init(cls, **options):
        '''Init an Azure service object using the local environment credentials

            Arguments:
                resource_group (str): the Azure resource group name

            All other options are passed along to __init__
        '''
        options['use_environment_for_auth'] = True
        s = Service(**options)
        if not s.subscription_id:
            s.subscription_id = s.connection().config.subscription_id
        if not s.tenant_id:
            try:
                s.tenant_id = next(s.connection('subscription').tenants.list()).tenant_id
            except Exception as e:
                log.debug(e)
                raise vFXTServiceFailure("Failed to lookup tenant")
        return s

    def find_instances(self, search=None):
        '''Returns all or filtered list of instances

            Arguments:
                search (str, optional): search name by string/regex

            Returns:
                [objs]: list of backend instance objects
        '''
        r = ''
        try:
            r = re.compile(search or r'')
        except Exception as e:
            log.debug("Search expression invalid {}: {}".format(search, e))
        return [_ for _ in self.connection().virtual_machines.list(self.resource_group) if re.search(r, _.name)]

    def get_instances(self, instance_ids):
        '''Returns a list of instances with the given instance ID list

            Arguments:
                instance_ids ([str]): list of instance id strings

            Returns:
                [objs]: list of backend instance objects
        '''
        return [_ for _ in self.find_instances() if _.name in instance_ids]

    def get_instance(self, instance_id):
        '''Get a specific instance by instance ID

            Arguments:
                instance_id (str)

            Returns:
                obj or None
        '''
        try:
            return self.connection().virtual_machines.get(self.resource_group, instance_id)
        except Exception:
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
                status_errors = [_ for _ in s if 'ProvisioningState/failed' in _]
                if status_errors:
                    raise vFXTServiceFailure("Instance {} failed: {}".format(instance.name, status_errors))
            except vFXTServiceFailure:
                raise
            except Exception as e:
                log.debug('Ignored: {}'.format(e))
                errors += 1
                time.sleep(backoff(errors))
            retries -= 1
            if retries == 0:
                raise vFXTServiceTimeout("Timed out waiting for {} on {}".format(status, instance.name))

    def wait_for_service_checks(self, instance, retries=ServiceBase.WAIT_FOR_SERVICE_CHECKS):
        # No MS Azure equivalent
        return True

    def _wait_for_operation(self, operation, msg='operation to complete', retries=ServiceBase.WAIT_FOR_OPERATION, status='Succeeded'):
        '''Wait for an operation to complete by polling the response

            Arguments:
                operation (string): operation object
                retries (int, optional): number of retries
                status (str, optional): status text

            Raises: vFXTServiceFailure
        '''
        while operation.status() != status: # the call to status() can block
            if retries % 10 == 0:
                log.debug("Waiting for {}: {}".format(msg, operation.status()))
            try:
                if operation.done() and operation.result().error: # an error, not a timeout
                    raise vFXTServiceFailure("Operation error waiting for {}: {}".format(msg, operation.result().error))
            except AttributeError: pass

            retries -= 1
            if retries == 0:
                raise vFXTServiceTimeout("Timed out waiting for {}".format(msg))
            time.sleep(self.POLLTIME)
        log.debug("Finishing waiting for {}: {}".format(msg, operation.status()))

    def stop(self, instance, wait=WAIT_FOR_STOP):
        '''Stop an instance

            Arguments:
                instance: backend instance
                wait (int, optional): wait time for operation to complete
        '''
        if not self.can_stop(instance):
            raise vFXTConfigurationException("Node configuration prevents them from being stopped")
        log.info("Stopping instance {}".format(self.name(instance)))
        conn = self.connection()
        # use deallocate (instead of stop) so that we do not get charged for the vm
        op = conn.virtual_machines.deallocate(self._instance_resource_group(instance), self.name(instance))
        self._wait_for_operation(op, msg='{} to stop'.format(self.name(instance)), retries=wait)

    def start(self, instance, wait=WAIT_FOR_START):
        '''Start an instance

            Arguments:
                instance: backend instance
                wait (int, optional): wait time for operation to complete
        '''
        log.info("Starting instance {}".format(self.name(instance)))
        conn = self.connection()
        op = conn.virtual_machines.start(self._instance_resource_group(instance), self.name(instance))
        self._wait_for_operation(op, msg='{} to start'.format(self.name(instance)), retries=wait)

    def restart(self, instance, wait=ServiceBase.WAIT_FOR_RESTART):
        '''Restart an instance

            Arguments:
                instance: backend instance
                wait (int): wait time
        '''
        if not self.can_stop(instance):
            raise vFXTConfigurationException("Node configuration prevents them from being restarted")
        log.info("Restarting instance {}".format(self.name(instance)))
        conn = self.connection()
        op = conn.virtual_machines.restart(self._instance_resource_group(instance), self.name(instance))
        self._wait_for_operation(op, msg='{} to restart'.format(self.name(instance)), retries=wait)

    def destroy(self, instance, wait=WAIT_FOR_DESTROY):
        '''Destroy an instance

            Arguments:
                instance: backend instance
                wait (int, optional): wait time for operation to complete
        '''
        log.info("Destroying instance {}".format(self.name(instance)))
        conn = self.connection()
        instance_resource_group = self._instance_resource_group(instance)

        try:
            op = conn.virtual_machines.delete(instance_resource_group, self.name(instance))
            # we wait because we cannot destroy resources still attached to the instance
            self._wait_for_operation(op, msg='{} to be destroyed'.format(self.name(instance)), retries=wait)
        except vFXTServiceTimeout as e:
            # Timeouts may just mean the azure python stack lost state...
            log.error(e)
            log.warning("Trying to clean up the rest of the resources for {}...".format(self.name(instance)))

        # Also need to delete any leftover disks
        try:
            if instance.storage_profile.os_disk.managed_disk:
                conn.disks.delete(instance_resource_group, instance.storage_profile.os_disk.name)
            elif instance.storage_profile.os_disk.vhd:
                disk = self._parse_vhd_uri(instance.storage_profile.os_disk.vhd.uri)
                self._delete_blob(**disk)
            else:
                log.warn("Unable to determine root disk type to clean up")

        except Exception as e:
            log.debug("Failed to delete root disk: {}".format(e))

        for data_disk in instance.storage_profile.data_disks:
            try:
                if data_disk.managed_disk:
                    conn.disks.delete(instance_resource_group, data_disk.name)
                elif data_disk.vhd:
                    disk = self._parse_vhd_uri(data_disk.vhd.uri)
                    self._delete_blob(**disk)
                else:
                    log.warn("Unable to determine data disk type to clean up")
            except Exception as e:
                log.debug("Failed to delete data disk: {}".format(e))

        # Also need to delete any leftover nics
        for nic_ref in instance.network_profile.network_interfaces:
            nic_id = nic_ref.id
            nic_name = nic_id.split('/')[-1]
            nic_rsg = nic_id.split('/')[4]
            try:
                self._delete_nic(nic_name, nic_rsg)
            except Exception as e:
                log.debug("Failed to delete NIC: {}".format(e))

    def is_on(self, instance):
        '''Return True if the instance is currently on

            Arguments:
                instance: backend instance
        '''
        status = self.status(instance)
        return status != self.OFF_STATUS and status != self.STOP_STATUS

    def is_off(self, instance):
        '''Return True if the instance is currently off

            Arguments:
                instance: backend instance
        '''
        status = self.status(instance)
        return status == self.OFF_STATUS or status == self.STOP_STATUS

    def name(self, instance):
        '''Returns the instance name (may be different from instance id)

            Arguments:
                instance: backend instance
        '''
        return instance.name

    def instance_id(self, instance):
        '''Returns the instance id (may be different from instance name)

            Arguments:
                instance: backend instance
        '''
        return instance.name

    def ip(self, instance):
        '''Return the primary IP address of the instance

            Arguments:
                instance: backend instance
        '''
        return self._instance_primary_nic(instance).ip_configurations[0].private_ip_address

    def _instance_primary_nic(self, instance):
        '''Return the primary network interface of the instance'''
        conn = self.connection('network')
        primary_nic_id = instance.network_profile.network_interfaces[0].id
        primary_nic_name = primary_nic_id.split('/')[-1]
        primary_nic_rsg = primary_nic_id.split('/')[4]
        return conn.network_interfaces.get(primary_nic_rsg, primary_nic_name)

    def _instance_resource_group(self, instance):
        return instance.id.split('/')[4]

    def _instance_subnet(self, instance):
        '''Return the subnet of an instance

            Arguments:
                instance: backend instance
        '''
        conn = self.connection('network')
        primary_nic = self._instance_primary_nic(instance)
        subnet_parts = primary_nic.ip_configurations[0].subnet.id.split('/')
        return conn.subnets.get(resource_group_name=subnet_parts[4], virtual_network_name=subnet_parts[-3], subnet_name=subnet_parts[-1])

    def _instance_network(self, instance):
        '''Return the network of the instance'''
        primary_nic = self._instance_primary_nic(instance)
        subnet_parts = primary_nic.ip_configurations[0].subnet.id.split('/')
        return self._get_network(network=subnet_parts[8], resource_group=subnet_parts[4])

    def _instance_identity_custom_role(self, instance):
        '''Return the custom role of the instance

            This is currently the role applied the system managed identity of the instance
        '''
        conn = self.connection('authorization')
        if not hasattr(instance, 'identity') and not hasattr(instance.identity, 'principal_id'):
            raise vFXTConfigurationException("Instance {} has no identity configuration".format(self.name(instance)))

        principal_id = instance.identity.principal_id
        role_assignments = [_ for _ in conn.role_assignments.list("principalId eq '{}'".format(principal_id))]
        roles = [conn.role_definitions.get_by_id(_.role_definition_id) for _ in role_assignments]
        custom_roles = [_ for _ in roles if _.role_type == 'CustomRole']
        if not custom_roles:
            raise vFXTConfigurationException("Unable to find custom role for {}".format(self.name(instance)))
        return custom_roles[0]

    def fqdn(self, instance):
        '''Provide the fully qualified domain name of the instance

            Arguments:
                instance: backend instance
        '''
        return instance.os_profile.computer_name

    def status(self, instance):
        '''Return the instance status

            Arguments:
                instance: backend instance
        '''
        conn = self.connection()
        return [_.code for _ in conn.virtual_machines.instance_view(self._instance_resource_group(instance), instance.name).statuses]

    def refresh(self, instance):
        '''Refresh the instance from the MS Azure backend

            Arguments:
                instance: backend instance
        '''
        return self.get_instance(instance.name)

    def can_stop(self, instance):
        '''Check whether this instance configuration can be stopped

            Arguments:
                instance: backend instance
        '''
        return True

    def create_instance(self, machine_type, name, boot_disk_image, other_disks=None, **options):
        '''Create and return an Azure instance

            Arguments:
                machine_type (str): Azure machine type
                name (str): name of the instance
                boot_disk_image (str): the name of the disk image for the root disk
                other_disks ([], optional): Azure disk definitions
                tags (dict, optional): tags to apply to instance
                resource_group (str, optional): Resource group for the instance
                admin_username (str, optional): defaults to avereadmin
                admin_password (str, optional): defaults to AvereAdminN0tUsed!
                admin_ssh_data (str, optional): SSH key data (used in place of the admin password)
                availability_set (str, optional): availability set name
                network_security_group (str, optional): network security group name
                location (str, optional): Azure location
                wait_for_success (int, optional): wait time for the instance to report success (default WAIT_FOR_SUCCESS)
                auto_public_address (bool, optional): auto assign a public address (defaults to False)
                root_disk_caching (str, optional): None, ReadOnly, ReadWrite (defaults to None)
                enable_boot_diagnostics (bool, optional): Turn on boot diagnostics
                advanced_networking (bool, optional): Turn on advanced networking (if image supports it)
                private_ip_address (str, optional): primary private IP address
                azure_role (str, optional): Azure role name to assign to the system provided identity
                identity (str, optional): ARM resource identity reference (full path)
                storage_account_type (str, optional): Storage account type for managed disks
                user_data (bytes, optional): Custom data for the instance CustomData field
        '''
        if not self.valid_instancename(name):
            raise vFXTConfigurationException("{} is not a valid instance name".format(name))
        if self.get_instance(name):
            raise vFXTConfigurationException("{} exists".format(name))

        conn           = self.connection()
        network        = options.get('network') or self.network
        subnet         = options.get('subnet') or self.subnets[0]
        location       = options.get('location') or self.location
        root_disk_name = '{}-root-{}'.format(name, int(time.time()))
        ip_forward     = options.get('enable_ip_forwarding') or False
        adv_networking = options.get('advanced_networking') or False
        wait_for_success = options.get('wait_for_success') or self.WAIT_FOR_SUCCESS
        role_name      = options.get('azure_role')
        resource_group = options.get('resource_group') or self.resource_group
        if role_name:
            _ = self._get_role(role_name) # validate

        # https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/createorupdate
        body = {
            'name': name,
            'location': location,
            'tags': options.get('tags') or {},
            'hardware_profile': {'vm_size': machine_type},
            'network_profile': {'network_interfaces': []},
            'storage_profile': {
                'data_disks': other_disks,
                'os_disk': {
                    'caching': options.get('root_disk_caching') or 'None',
                    'name': root_disk_name,
                    'managed_disk': {'storage_account_type': options.get('storage_account_type') or self.DEFAULT_STORAGE_ACCOUNT_TYPE},
                    'create_option': 'FromImage',
                    #'disk_size_gb': options.get('root_size') or None,
                },
            },
            'os_profile': {
                'computer_name': name,
                'admin_username': options.get('admin_username') or 'avereadmin',
                'admin_password': options.get('admin_password') or 'AvereAdminN0tUsed!',
                'linux_configuration': {'disable_password_authentication': False},
                'custom_data': None,
            },
            'identity': {
                'type': 'SystemAssigned',
            }
        }

        if body['tags']:
            if len(body['tags']) > 15:
                raise vFXTConfigurationException("Resources cannot have more than 15 tags")
            if any([len(_) > 512 for _  in body['tags']]):
                raise vFXTConfigurationException("Tag names cannot exceed 512 characters")
            if any([len(body['tags'][_]) > 256 for _  in body['tags']]):
                raise vFXTConfigurationException("Tag names cannot exceed 256 characters")

        admin_ssh_data = options.get('admin_ssh_data') or None
        if admin_ssh_data:
            del body['os_profile']['admin_password']
            body['os_profile']['linux_configuration']['disable_password_authentication'] = True
            ssh_config = {
                'public_keys': [{
                    'path': '/home/{}/.ssh/authorized_keys'.format(body['os_profile']['admin_username']),
                    'key_data': admin_ssh_data
                }]
            }
            body['os_profile']['linux_configuration']['ssh'] = ssh_config

        availability_set = options.get('availability_set') or None
        if availability_set:
            try:
                a_set = conn.availability_sets.get(resource_group, availability_set)
                body['availability_set'] = {'id': a_set.id}
            except Exception as e:
                raise vFXTServiceFailure("Failed to lookup availability set {}: {}".format(availability_set, e))

        identity = options.get('identity') or None
        if identity:
            body['identity']['type'] = 'UserAssigned'
            body['identity']['identity_ids'] = [identity]

        # determine where we are getting the root disk
        # if its a url and in our storage account, use it directly
        boot_disk_image_url = urlparse.urlparse(boot_disk_image)
        blob_host = 'blob.{}'.format(self.storage_suffix) if self.storage_suffix else self.BLOB_HOST
        if boot_disk_image_url.hostname == '{}.{}'.format(self.storage_account, blob_host):
            log.info("Using local image {}".format(boot_disk_image))
            img = self._create_image_from_vhd(boot_disk_image)
            body['storage_profile']['image_reference'] = {'id': img.id}
        # if its some other azure storage account, copy it in (only if we have a configured storage account)
        elif self.storage_account and boot_disk_image_url.hostname and boot_disk_image_url.hostname.endswith(blob_host):

            blob_name = 'Microsoft.Compute/Images/vhds/{}'.format(boot_disk_image_url.path.split('/')[-1])
            local_blob_url = self.BLOB_URL_FMT.format(self.storage_account, blob_host, self.SYSTEM_CONTAINER, blob_name)

            try:
                self.create_container('{}/{}'.format(self.storage_account, self.SYSTEM_CONTAINER))
            except ContainerExistsException: pass

            # Simple existing check... there may be better ways if we want to invalidate our existing copy
            if not self._blob_exists(self.storage_account, self.SYSTEM_CONTAINER, blob_name):
                try:
                    self._copy_blob(boot_disk_image, blob_name, container=self.SYSTEM_CONTAINER, storage_account=self.storage_account)
                except Exception as e:
                    raise vFXTServiceFailure("Failed to copy image {}: {}".format(boot_disk_image, e))
            else:
                log.debug("Using existing blob {} in storage account {}".format(blob_name, self.storage_account))

            img = self._create_image_from_vhd(local_blob_url)
            body['storage_profile']['image_reference'] = {'id': img.id}

        # if its a marketplace path like OpenLogic:CentOS:7.1:latest
        elif boot_disk_image.count(':') == 3: # must be marketplace
            log.info("Using marketplace URN {}".format(boot_disk_image))
            pub, offer, sku, version = boot_disk_image.split(':')
            body['storage_profile']['image_reference'] = {
                "publisher": pub,
                "offer": offer,
                "sku": sku,
                "version": version
            }
            if pub == 'microsoft-avere':
                body['plan'] = {
                    "publisher": pub,
                    "product": offer,
                    "name": sku,
                }
        else:
            # assume it is a managed image in our resource group
            try:
                img = conn.images.get(resource_group, boot_disk_image)
                body['storage_profile']['image_reference'] = {'id': img.id}
            except Exception as e:
                log.debug("Failed to find image: {}".format(e))
                raise vFXTConfigurationException("Unable to handle boot disk {}".format(boot_disk_image))

        # if we turn on boot diagnostics, log to our non-premium account
        if options.get('enable_boot_diagnostics'):
            blob_host = 'blob.{}'.format(self.storage_suffix) if self.storage_suffix else self.BLOB_HOST
            boot_diagnostics_storage_account = options.get('boot_diagnostics_storage') or self.storage_account
            if not boot_diagnostics_storage_account:
                raise vFXTConfigurationException("No storage account provided for boot diagnostics")
            body['diagnostics_profile'] = {'boot_diagnostics': {
                'enabled': True,
                'storage_uri': 'https://{}.{}'.format(boot_diagnostics_storage_account, blob_host)
            }}

        # base64 encoded user data
        user_data = options.get('user_data') or None
        if user_data:
            body['os_profile']['custom_data'] = user_data.encode('base64').replace('\n','').strip()

        # network interface
        network_security_group = options.get('network_security_group') or self.network_security_group
        public_ip_address = options.get('auto_public_address', False)
        nic = None
        try:
            nic = self._create_nic('{}-1-NIC-{}'.format(name, int(time.time())),
                network=network,
                subnet=subnet,
                resource_group=resource_group, # use compute resource group for NICs
                network_security_group=network_security_group,
                enable_ip_forwarding=ip_forward,
                enable_public_address=public_ip_address,
                advanced_networking=adv_networking,
                private_address=options.get('private_ip_address') or None
            )
            nic_cfg = {'id': nic.id} # XXX 'primary': True
            body['network_profile']['network_interfaces'].append(nic_cfg)
        except Exception as e:
            log.debug(e)
            raise vFXTServiceFailure("Failed to create NIC: {}".format(e))

        log.debug("Create instance request body: {}".format(body))

        try:
            # if we have to synchronize so that our vm creations batch properly
            azure_nic_barrier = options.get('_azure_nic_barrier')
            if azure_nic_barrier:
                try:
                    azure_nic_barrier.wait()
                except BarrierTimeout:
                    raise vFXTServiceFailure("Failed waiting for all network interfaces to create.")

            op = conn.virtual_machines.create_or_update(resource_group, name, body)
            wait_for_success = options.get('wait_for_success') or self.WAIT_FOR_SUCCESS
            self._wait_for_operation(op, msg="instance {} to be created".format(name), retries=wait_for_success)
            instance = conn.virtual_machines.get(resource_group, name)

            # assign the role to node managed identity here
            if role_name:
                self._assign_role(instance.identity.principal_id, role_name)

            self.wait_for_status(instance, self.ON_STATUS, wait_for_success)
            return instance
        except Exception as e:
            log.debug("Failed to create instance: {}".format(e))

            # try and give some error
            try:
                instance_view = conn.virtual_machines.instance_view(resource_group, name)
                if instance_view.statuses:
                    for status in instance_view.statuses or []:
                        log.debug("Instance view status for {}: {}".format(name, status))
                        if status.level.name == 'error' and status.message:
                            log.error("Instance create error for {}: {}".format(name, status.message))
                if instance_view.disks:
                    for disk in instance_view.disks or []:
                        for status in disk.statuses:
                            log.debug("Instance view disk status for {}: {}".format(disk.name, status))
                            if status.level.name == 'error' and status.message:
                                log.error("Instance disk create error for {}: {}".format(disk.name, status.message))
            except Exception as instance_e:
                log.debug("Failed while trying to read failed instance {}: {}".format(name, instance_e))

            try: # it seems we have to manually delete a failed instance
                op = conn.virtual_machines.delete(resource_group, name)
                self._wait_for_operation(op, msg='instance {} to be destroyed'.format(name), retries=self.WAIT_FOR_DESTROY)
            except Exception as instance_e:
                log.debug("Failed while cleaning up instance: {}".format(instance_e))

            if public_ip_address:
                try:
                    op = self.connection('network').public_ip_addresses.delete(resource_group, '{}-public-address'.format(name))
                    self._wait_for_operation(op, msg="public IP address to be removed")
                except Exception as addr_e:
                    log.debug("Failed while cleaning up public address: {}".format(addr_e))

            # delete nic
            try:
                if nic:
                    self.connection('network').network_interfaces.delete(resource_group, nic.name)
            except Exception as nic_e:
                log.debug("Failed while cleaning up instance NIC: {}".format(nic_e))

            # delete root disk if we did not attach it
            if body['storage_profile']['os_disk']['create_option'] != 'Attach':
                try:
                    conn.disks.delete(resource_group, root_disk_name)
                except Exception as root_disk_e:
                    log.debug("Failed while cleaning up instance root disk: {}".format(root_disk_e))

            # delete data disks if we have them
            if other_disks:
                for disk in other_disks:
                    try:
                        if disk.get('managed_disk') and disk.get('name'):
                            conn.disks.delete(resource_group, disk['name'])
                        else:
                            vhd_data = self._parse_vhd_uri(disk['vhd']['uri'])
                            self._delete_blob(**vhd_data)
                    except Exception as data_disk_e:
                        log.debug("Failed while cleaning up instance data disk: {}".format(data_disk_e))

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
                    data_disk_size (int): size of data disks
                    data_disk_count (int): number of data disks
                    data_disk_caching (str, optional): None, ReadOnly, ReadWrite (defaults to ReadOnly)
                    machine_type (str): machine type
                    root_image (str): VHD ID

        '''
        if self.get_instance(node_name):
            raise vFXTNodeExistsException("Node {} exists".format(node_name))

        data_disk_disks = []
        data_disk_caching = node_opts.get('data_disk_caching') or 'ReadOnly'
        for idx in xrange(node_opts['data_disk_count']):
            disk_name = '{}-data_disk-{}-{}'.format(node_name, idx, int(time.time()))
            data_disk = {
                'name': disk_name,
                'disk_size_gb': node_opts['data_disk_size'],
                'create_option': 'Empty',
                'caching': data_disk_caching,
                'managed_disk': {'storage_account_type': self.DEFAULT_STORAGE_ACCOUNT_TYPE},
                'lun': str(idx),
            }
            data_disk_disks.append(data_disk)

        log.info("Creating node {}".format(node_name))
        n = self.create_instance(machine_type=node_opts['machine_type'],
            name=node_name,
            boot_disk_image=node_opts['root_image'],
            other_disks=data_disk_disks,
            user_data=cfg,
            enable_ip_forwarding=True,
            advanced_networking=True,
            **instance_options
        )
        log.info("Created {} ({})".format(self.name(n), self.ip(n)))
        return n

    def create_cluster(self, cluster, **options):
        '''Create a vFXT cluster (calls create_node for each node)
            Typically called via vFXT.Cluster.create()

            Arguments:
                cluster (vFXT.cluster.Cluster): cluster object
                size (int, optional): size of cluster (node count)
                root_image (str, optional): root disk image name
                data_disk_size (int, optional): size of data disk (or machine type default)
                data_disk_count (int, optional): number of data disks (or machine type default)
                data_disk_caching (str, optional): None, ReadOnly, ReadWrite (defaults to DEFAULT_CACHING_OPTION)
                root_disk_caching (str, optional): None, ReadOnly, ReadWrite (defaults to DEFAULT_CACHING_OPTION)
                wait_for_state (str, optional): red, yellow, green cluster state (defaults to yellow)
                skip_cleanup (bool, optional): do not clean up on failure
                azure_role (str, optional): Azure role name for the service principal (otherwise one is created)
                availability_set (str, optional): existing availability set for the cluster instances
                subnets ([str], optional): one or more subnets
                location (str, optional): location for availability set
                management_address (str, optional): management address for the cluster
                instance_addresses ([], optional): list of instance addresses to use (passed to create_cluster(private_ip_address))
                address_range_start (str, optional): The first of a custom range of addresses to use for the cluster
                address_range_end (str, optional): The last of a custom range of addresses to use for the cluster
                address_range_netmask (str, optional): cluster address range netmask

                Additional arguments are passed through to create_node()

            Raises: vFXTConfigurationException, vFXTCreateFailure
        '''
        cluster.availability_set = None
        cluster.role = None

        if not all([cluster.mgmt_ip, cluster.mgmt_netmask, cluster.cluster_ip_start, cluster.cluster_ip_end]):
            raise vFXTConfigurationException("Cluster networking configuration is incomplete")

        machine_type    = cluster.machine_type
        if machine_type not in self.MACHINE_DEFAULTS:
            raise vFXTConfigurationException('{} is not a valid instance type'.format(machine_type))
        machine_defs    = self.MACHINE_DEFAULTS[machine_type]
        cluster_size    = int(options.get('size', machine_defs['node_count']))
        subnets         = options.get('subnets') or self.subnets
        subnets         = [subnets] if isinstance(subnets, basestring) else subnets
        cluster.subnets = [subnets[0]] # first node subnet
        cluster.network_security_group = options.get('network_security_group') or self.network_security_group

        # disk sizing
        root_image        = options.get('root_image')      or self._get_default_image()
        data_disk_size    = options.get('data_disk_size')  or machine_defs['data_disk_size']
        data_disk_count   = options.get('data_disk_count') or machine_defs['data_disk_count']
        data_disk_caching = options.get('data_disk_caching') or self.DEFAULT_CACHING_OPTION
        options.setdefault('root_disk_caching', self.DEFAULT_CACHING_OPTION)

        # verify our data_disk_size is in self.VALID_DATA_DISK_SIZES
        if data_disk_size not in self.VALID_DATA_DISK_SIZES:
            raise vFXTConfigurationException('{} is not in the allowed disk size list: {}'.format(data_disk_size, self.VALID_DATA_DISK_SIZES))

        if data_disk_count > machine_defs['max_data_disk_count']:
            raise vFXTConfigurationException('{} exceeds the maximum allowed disk count of {}'.format(data_disk_count, machine_defs['max_data_disk_count']))

        instance_addresses = cluster.instance_addresses or [None] * cluster_size
        subnet = self.connection('network').subnets.get(self.network_resource_group, self.network, subnets[0])
        if not Cidr(subnet.address_prefix).contains(cluster.cluster_ip_start):
            raise vFXTConfigurationException("Cluster addresses must reside within subnet {}".format(subnets[0]))
        if instance_addresses[0]: # must be defined, not None
            if not Cidr(subnet.address_prefix).contains(instance_addresses[0]):
                raise vFXTConfigurationException("Cluster addresses must reside within subnet {}".format(subnets[0]))

        log.info('Creating cluster configuration')
        cfg = cluster.cluster_config(expiration=options.get('config_expiration', None))
        log.debug("Generated cluster config: {}".format(cfg.replace(cluster.admin_password, '[redacted]')))

        try:
            role = options.get('azure_role') or None
            if not role:
                # create a role if we were not provided one, later we will
                # assign it to the instance identity
                role_name = '{}-cluster-role'.format(cluster.name)
                log.info('Creating cluster role {}'.format(role_name))
                cluster.role = self._create_role(role_name)
                options['azure_role'] = role_name # pass it along to the nodes
            else:
                log.info('Using existing cluster role {}'.format(role))
                cluster.role = self._get_role(role)

            # availability set (we can keep creating it as it is just an update operation)
            availability_set = options.get('availability_set') or '{}-availability_set'.format(cluster.name)
            cluster.availability_set = self._create_availability_set(availability_set)
            options['availability_set'] = availability_set

            # create the initial node
            name = '{}-{:02}'.format(cluster.name, 1)
            opts = {'data_disk_count': data_disk_count, 'data_disk_size': data_disk_size, 'data_disk_caching': data_disk_caching,
                    'machine_type': machine_type, 'root_image': root_image,
                    }
            options['subnet'] = subnets[0] # first node subnet
            options['private_ip_address'] = instance_addresses.pop(0)
            n = self.create_node(name, cfg, node_opts=opts, instance_options=options)
            cluster.nodes.append(ServiceInstance(service=self, instance=n))

            threads = []
            if not options.get('skip_configuration'):
                t = threading.Thread(target=cluster.first_node_configuration)
                t.setDaemon(True)
                t.start()
                threads.append(t)
            options.update(opts)
            options['subnet'] = subnets if len(subnets) == 1 else subnets[1:]
            options['instance_addresses'] = instance_addresses
            self.add_cluster_nodes(cluster, cluster_size - 1, **options)
            # do a timeout join to handle KeyboardInterrupts
            while all([_.is_alive() for _ in threads]):
                for t in threads:
                    t.join()
            if cluster.first_node_error:
                raise cluster.first_node_error
        except vFXTNodeExistsException as e:
            log.error("Failed to create node: {}".format(e))
            raise
        except Exception as e:
            if not log.isEnabledFor(logging.DEBUG):
                log.exception(e)
            log.error("Failed to create nodes: {}".format(e))
            if not options.get('skip_cleanup', False):
                cluster.destroy(quick_destroy=True)
            raise vFXTCreateFailure(e)


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

        subnets         = options.get('subnets') or cluster.subnets if hasattr(cluster, 'subnets') else self.subnets
        subnets         = [subnets] if isinstance(subnets, basestring) else subnets
        # make sure to use unused subnets first, but account for our cluster subnets
        subnets.extend([s for s in cluster.subnets if s not in subnets])
        cycle_subnets   = cycle(subnets)

        # look at cluster.nodes[0].instance
        instance          = cluster.nodes[0].instance
        data_disk_count   = options.get('data_disk_count') or len(instance.storage_profile.data_disks)
        data_disk_size    = options.get('data_disk_size') or instance.storage_profile.data_disks[0].disk_size_gb
        data_disk_caching = options.get('data_disk_caching') or instance.storage_profile.data_disks[0].caching.value
        root_image        = options.get('root_image') or None
        tags              = options.get('tags') or instance.tags or {}
        machine_type      = cluster.machine_type
        availability_set  = cluster.availability_set.name if cluster.availability_set else None

        instance_addresses = options.pop('instance_addresses', [None] * count)
        if len(instance_addresses) != count:
            raise vFXTConfigurationException("Not enough instance addresses provided, require {}".format(count))
        # our instance addresses must always reside within the subnet
        if instance_addresses[0]: # must be defined, not None
            subnet = self.connection('network').subnets.get(self.network_resource_group, self.network, subnets[0])
            if not Cidr(subnet.address_prefix).contains(instance_addresses[0]):
                raise vFXTConfigurationException("Cluster addresses must reside within subnet {}".format(subnets[0]))

        try:
            if instance.os_profile.linux_configuration.ssh and 'admin_ssh_data' not in options:
                options['admin_ssh_data'] = instance.os_profile.linux_configuration.ssh.public_keys[0].key_data
        except Exception: pass

        if cluster.role:
            options['azure_role'] = cluster.role.role_name

        # set network security group for added nodes
        options['network_security_group'] = cluster.network_security_group

        if tags and 'tags' not in options:
            options['tags'] = tags
        if availability_set and 'availability_set' not in options:
            options['availability_set'] = availability_set

        if not root_image:
            if instance.storage_profile.os_disk.image: # old vhd style
                root_image = instance.storage_profile.os_disk.image.uri
            elif instance.storage_profile.image_reference: # managed
                if instance.storage_profile.image_reference.id:
                    root_image = instance.storage_profile.image_reference.id.split('/')[-1]
                else:
                    publisher = instance.storage_profile.image_reference.publisher
                    offer = instance.storage_profile.image_reference.offer
                    sku = instance.storage_profile.image_reference.sku
                    version = instance.storage_profile.image_reference.version
                    if not all([publisher, offer, sku, version]):
                        log.debug(instance.storage_profile.image_reference.__dict__)
                        raise vFXTConfigurationException("Unable to determine root disk image to use")
                    root_image = '{}:{}:{}:{}'.format(publisher, offer, sku, version)
            else:
                raise vFXTConfigurationException("Unable to determine root disk image to use")

        opts = {'data_disk_size': data_disk_size, 'data_disk_count': data_disk_count, 'data_disk_caching': data_disk_caching,
                'machine_type': machine_type, 'root_image': root_image,
        }
        # overrides
        overrides = ['machine_type', 'root_image', 'data_disk_size']
        for o in overrides:
            if o in options:
                opts[o] = options.pop(o)

        # Requires cluster be online
        # XXX assume our node name always ends in the node number
        max_node_num = max([int(i.name().split('-')[-1]) for i in cluster.nodes])
        joincfg     = cluster.cluster_config(joining=True, expiration=options.get('config_expiration', None))

        nodeq   = Queue.Queue()
        failq   = Queue.Queue()
        threads = []
        options['_azure_nic_barrier'] = Barrier(count, self.WAIT_FOR_SUCCESS)

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

        for node_num in xrange(max_node_num, max_node_num+count):
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

    def post_destroy_cluster(self, cluster):
        '''Post cluster destroy cleanup'''
        # We may not have permissions to delete a role
        #try:
        #    if hasattr(cluster, 'role'):
        #        if cluster.role:
        #            # this will fail if we do not have permissions
        #            self._delete_role(cluster.role.role_name)
        #except Exception as e:
        #    log.debug('Ignoring cluster role cleanup error: {}'.format(e))
        try:
            if hasattr(cluster, 'availability_set'):
                if cluster.availability_set:
                    self._delete_availability_set(cluster.availability_set.name)
        except Exception as e:
            log.debug('Ignoring availability set cleanup error: {}'.format(e))

    def load_cluster_information(self, cluster, **options):
        '''Loads cluster information from the service and cluster itself
        '''
        xmlrpc = cluster.xmlrpc()

        # make sure mgmt_ip is set to the valid address (in case we used
        # a node address to get in)
        cluster.mgmt_ip = xmlrpc.cluster.get()['mgmtIP']['IP']
        cluster.network_security_group = None

        node_ips = set([n['primaryClusterIP']['IP']
                        for name in xmlrpc.node.list()
                        for n in [xmlrpc.node.get(name)[name]]
                        if 'primaryClusterIP' in n])

        instances = set()
        for nic in self.connection('network').network_interfaces.list_all():
            for ip_config in nic.ip_configurations:
                if ip_config.private_ip_address in node_ips:
                    if not nic.virtual_machine or not nic.virtual_machine.id:
                        raise vFXTServiceFailure("Network interface is not attached to any instances: {}".format(nic.name))
                    instances.add(nic.virtual_machine.id.split('/')[-1])
        instances = list(instances)

        if instances:
            cluster.nodes = []
            for i in instances:
                cluster.nodes.append(ServiceInstance(self, i))

            instances = [_.instance for _ in cluster.nodes]

            # subnet info
            cluster.subnets = list(set([self._instance_subnet(i).name for i in instances]))

            # XXX assume all instances have the same settings
            cluster.location         = instances[0].location
            cluster.machine_type     = instances[0].hardware_profile.vm_size
            cluster.availability_set = None
            if instances[0].availability_set:
                availability_set = instances[0].availability_set.id.split('/')[-1]
                cluster.availability_set = self.connection().availability_sets.get(cluster.service.resource_group, availability_set)

            cluster.name = self.CLUSTER_NODE_NAME_RE.search(cluster.nodes[0].name()).groups()[0]
            cluster.role = None
            try: # try and find the cluster role
                cluster.role = self._instance_identity_custom_role(instances[0])
            except Exception as e:
                log.debug("Failed to lookup cluster role: {}".format(e))

            # try and find the network security group
            try:
                nic = self._instance_primary_nic(instances[0])
                if nic.network_security_group:
                    cluster.service.network_security_group = nic.network_security_group.id.split('/')[-1]
            except Exception as e:
                if not log.isEnabledFor(logging.DEBUG):
                    log.exception(e)
                log.debug("Failed trying to lookup network security group: {}".format(e))

    def _commit_instance(self, instance, body):
        '''Commit changes to the instance with the backend

            Arguments:
                instance: backend instance
                body: serialized data

            Returns an updated backend instance
        '''
        conn = self.connection()
        try:
            op = conn.virtual_machines.create_or_update(self._instance_resource_group(instance), instance.name, body)
            self._wait_for_operation(op, msg="{} to be updated".format(self.name(instance)), retries=self.WAIT_FOR_SUCCESS)
            return self.refresh(instance)
        except Exception as e:
            raise vFXTServiceFailure("Failed to commit instance changes: {}".format(e))

    def shelve(self, instance):
        ''' shelve the instance; shut it down, detach and delete
            all non-root block devices

            Arguments:
                instance: backend instance
            Raises: vFXTServiceFailure
        '''
        instance = self.refresh(instance)
        if not self.can_shelve(instance):
            raise vFXTConfigurationException("{} configuration prevents shelving".format(self.name(instance)))
        if self.is_shelved(instance):
            raise vFXTConfigurationException("{} is already shelved".format(self.name(instance)))

        if self.is_on(instance):
            self.stop(instance)
            instance = self.refresh(instance)

        if not instance.storage_profile.data_disks:
            log.info("No non-root volumes for instance {}, already shelved?".format(self.name(instance)))
            return

        data_disks        = instance.storage_profile.data_disks
        data_disk_count   = len(data_disks)
        data_disk_size    = data_disks[0].disk_size_gb
        data_disk_caching = data_disks[0].caching.value

        body = instance.serialize()
        body['properties']['storageProfile']['dataDisks'] = []
        instance = self._commit_instance(instance, body)
        self.wait_for_status(instance, self.OFF_STATUS, self.WAIT_FOR_STOP)

        # delete the disk blobs
        errors = ShelveErrors()
        failed = []
        for data_disk in data_disks:
            vhd_data = self._parse_vhd_uri(data_disk.vhd.uri)
            try:
                self._delete_blob(**vhd_data)
            except Exception as e:
                log.debug(e)
                failed.append(vhd_data['blob'])
        if failed:
            errors['notdeleted'] = ','.join(failed)

        shelved = "{}|{}|{}".format(data_disk_count, data_disk_size, data_disk_caching)
        if errors:
            shelved += '|{}'.format(errors)

        # tag and commit our instance metadata to the backend
        try:
            body = instance.serialize()
            body['tags']['shelved'] = shelved
            instance = self._commit_instance(instance, body)
            self.wait_for_status(instance, self.OFF_STATUS)
        except Exception as e:
            log.debug(e)
            raise vFXTServiceFailure("Failed to shelve instance {}: {}".format(instance['name'], e))

    def can_shelve(self, instance):
        ''' Some instance configurations cannot be shelved. Check if this is one.

            Arguments:
                instance: backend instance
        '''
        return True

    def is_shelved(self, instance):
        '''Return True if the instance is currently shelved

            Arguments:
                instance: backend instance
        '''
        try:
            if 'shelved' in instance.tags:
                return True
        except Exception as e:
            log.debug(e)
        return False

    def unshelve(self, instance, count_override=None, size_override=None, type_override=None, **options): #pylint: disable=unused-argument
        ''' bring our instance back to life.  This requires a tag called
            shelved that contains the number of disks and their size/type

            Arguments:
                instance: backend instance
                count_override (int, optional): number of data disks
                size_override (int, optional): size of data disks
                type_override (str, optional): type of data caching

            Raises: vFXTServiceFailure
        '''
        instance = self.refresh(instance)
        if not self.is_shelved(instance):
            log.info( "{} does not have shelved tag, skipping".format(instance['name']))
            return

        # check that instance is already stopped
        if self.is_on(instance):
            log.info("{} is not stopped, skipping".format(instance['name']))
            return

        try:
            attrs = instance.tags['shelved'].split('|')
            data_disk_count, data_disk_size, data_disk_caching = attrs[0:3]
        except Exception:
            log.error("{} does not have data in the shelved tag".format(instance['name']))
            return

        if count_override:
            data_disk_count = count_override
        if size_override:
            data_disk_size = size_override
        if type_override:
            data_disk_caching = type_override

        data_disks = []
        for idx in xrange(int(data_disk_count)):
            disk_name = '{}-data_disk-{}-{}'.format(self.name(instance), idx, int(time.time()))
            # TODO maybe we could check shelve error for disk, query it exists
            # and use createOption: Attach
            data_disks.append({
                'name': disk_name,
                'diskSizeGB': data_disk_size,
                'createOption': 'Empty',
                'caching': data_disk_caching,
                'managed_disk': {'storage_account_type': options.get('storage_account_type') or self.DEFAULT_STORAGE_ACCOUNT_TYPE},
                'lun': str(idx),
            })
        try:
            body = instance.serialize()
            body['properties']['storageProfile']['dataDisks'] = data_disks
            del body['tags']['shelved']
            instance = self._commit_instance(instance, body)
            self.wait_for_status(instance, self.OFF_STATUS)
        except Exception as e:
            log.debug(e)
            raise vFXTServiceFailure("Failed to shelve instance {}: {}".format(instance['name'], e))
        self.start(instance)

    def _container_name(self, name):
        '''Split storage_account/container into (container, storage_account)'''
        parts = name.split('/')
        if len(parts) == 2: # storage_account/container
            return (parts[1], parts[0])
        elif len(parts) == 1: # no storage account specified, use service.storage_account
            return (name, self.storage_account)
        else:
            raise vFXTConfigurationException("Invalid container name {}, must be storage_account/container".format(name))

    def create_container(self, name, **options):
        '''Create a container

            Arguments:
                name (str): container name in the form of storage_account/container
                tags (dict, optional): tags to apply to the container

            Raises: vFXTServiceFailure
        '''
        container, storage_account = self._container_name(name)
        if not storage_account:
            raise vFXTConfigurationException("No storage account provided")

        if not self.valid_containername(container):
            raise vFXTConfigurationException("{} is not a valid container name".format(container))

        log.debug("Creating container {} in storage account {}".format(container, storage_account))

        blob_srv = self.connection('blobstorage', storage_account=storage_account)

        # check for existing
        if container in [_.name for _ in blob_srv.list_containers()]:
            raise ContainerExistsException("The container {} already exists for storage account {}".format(container, storage_account))

        rv = blob_srv.create_container(container, metadata=options.get('tags'))
        if not rv:
            raise vFXTServiceFailure("Failed to create container {}".format(container))
        return blob_srv.get_container_properties(container)

    def delete_container(self, name):
        '''Delete a container

            Arguments:
                name (str): container name in the form of storage_account/container

            Raises: vFXTServiceFailure, vFXTConfigurationException

            If the container is not empty, vFXTConfigurationException is raised
        '''
        container, storage_account = self._container_name(name)

        blob_srv = self.connection('blobstorage', storage_account=storage_account)

        if next(iter(blob_srv.list_blobs(container)), None):
            raise vFXTConfigurationException("Container {} not empty".format(container))
        rv = blob_srv.delete_container(container)
        if not rv:
            raise vFXTServiceFailure("Failed to delete container {}".format(container))

    def authorize_container(self, cluster, name, retries=ServiceBase.CLOUD_API_RETRIES, xmlrpc=None):
        '''Perform any backend work for the container, and register a credential
        for it to the cluster.  Returns the credential name for use with other API calls.

            No authorization is currently performed for Azure.

            Arguments:
                cluster (Cluster): cluster object
                name (str): bucket name
                retries (int, optional): number of attempts to make
                xmlrpc (xmlrpcClt, optional): number of attempts to make

            Raises: vFXTServiceFailure
        '''
        container, storage_account = self._container_name(name) # pylint: disable=unused-variable
        blob_srv = self.connection('blobstorage', storage_account=storage_account)

        try:
            storage_account_props = self.connection('storage').storage_accounts.get_properties(self.storage_resource_group, storage_account)
            if storage_account_props.sku.tier.name == 'premium':
                raise Exception("Premium tier storage accounts are not supported")

            log.debug("storage account type {}".format(storage_account_props.sku.name.value))
        except Exception as e:
            log.debug("Failed to validate storage account: {}".format(e))
            raise vFXTConfigurationException("{} is not a valid storage account: {}".format(storage_account, e))

        xmlrpc = cluster.xmlrpc() if xmlrpc is None else xmlrpc

        existing_creds = cluster._xmlrpc_do(xmlrpc.corefiler.listCredentials)

        # if we have an existing MSI cred, use it only if we are using the compute resource group
        if self.resource_group == self.storage_resource_group:
            for cred in existing_creds:
                if cred['type'] == self.COREFILER_CRED_MSI:
                    return cred['name']

        cred_name = 'azure-storage-{}'.format(storage_account)
        # if it exists, use it
        if cred_name in [c['name'] for c in existing_creds]:
            return cred_name
        # otherwise create it
        cred_body = {
            'subscription': self.subscription_id,
            'tenant': self.tenant_id,
            'storageKey': 'BASE64:{}'.format(blob_srv.authentication.account_key),
        }
        log.debug("Creating credential {}".format(cred_name))
        r = cluster._xmlrpc_do(xmlrpc.corefiler.createCredential, cred_name, self.COREFILER_CRED_TYPE, cred_body, _xmlrpc_do_retries=retries)
        if r != 'success':
            raise vFXTConfigurationException("Could not create credential {}: {}".format(cred_name, r))
        return cred_name

    # alias for api compatibility
    create_bucket = create_container
    delete_bucket = delete_container
    authorize_bucket = authorize_container

    def get_default_router(self, subnet_id=None):
        '''Get default route address

            Arguments:
                subnet_id (str): subnet id (optional if given to constructor)
            Returns:
                str: address of default router
        '''
        subnet_id   = subnet_id or self.subnets[0]
        conn        = self.connection('network')
        subnet      = conn.subnets.get(self.network_resource_group, self.network, self.subnets[0])
        c           = Cidr(subnet.address_prefix)
        return c.to_address(c.start()+1)

    def get_dns_servers(self):
        '''Get DNS server addresses
        '''
        try:
            if self.network:
                network = self._get_network()
                if network.dhcp_options and network.dhcp_options.dns_servers:
                    return network.dhcp_options.dns_servers
                log.debug("No dns configuration in the network DHCP options")
        except Exception as e:
            log.debug("Failed to look up environment dns configuration: {}".format(e))
        return self.DNS_SERVERS

    def get_ntp_servers(self):
        '''Get NTP server addresses
        '''
        return self.NTP_SERVERS

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
        addr_range = addr_range or self.private_range
        netmask = '255.255.255.255'

        conn = self.connection('network')
        network = self._get_network()

        if not addr_range:
            for subnet in network.subnets:
                if subnet.name == self.subnets[0]:
                    addr_range = subnet.address_prefix
                    log.debug("Using range {} from subnet {}".format(addr_range, subnet.name))
                    break
            if not addr_range:
                raise vFXTConfigurationException("Unable to find subnet {}".format(self.subnets[0]))
        else:
            log.debug("Using specified address range {}".format(addr_range))

        used = set(self.in_use_addresses(addr_range))
        if in_use:
            used.update(in_use)

        cidr = Cidr(addr_range)
        generator = cidr.addresses()
        # skip first reserved
        for _ in range(0, 4):
            used.add(next(generator))

        try:
            avail = []
            for address in generator:
                if address in used:
                    continue
                check = conn.virtual_networks.check_ip_address_availability(self.network_resource_group, network.name, address)
                if not check.available:
                    # mark a range as used from this address to the address *before* the next available address as reported
                    used.update(Cidr.expand_address_range(address, Cidr.to_address(Cidr.from_address(check.available_ip_addresses[0])-1)))
                if avail and contiguous:
                    if Cidr.from_address(avail[-1]) != Cidr.from_address(address)-1:
                        # if we wanted a contiguous list start over if the last found isn't just before the current address
                        avail = []
                avail.append(address)
                if len(avail) == count:
                    break
            else:
                raise vFXTConfigurationException("Check that the subnet or specified address range has enough free addresses")

            if not netmask:
                netmask = cidr.netmask
            return (avail, netmask)
        except vFXTConfigurationException:
            raise
        except Exception as e:
            raise vFXTConfigurationException("Check that the subnet or specified address range has enough free addresses: {}".format(e))

    def add_instance_address(self, instance, address, **options):
        '''Add a new address to the instance

            Arguments:
                instance: backend instance
                address (str): IP address
                allow_reassignment (bool, optional): defaults to True

            Raises: vFXTServiceFailure
        '''
        if address in self.instance_in_use_addresses(instance):
            raise vFXTConfigurationException("{} already assigned to {}".format(address, self.name(instance)))

        conn = self.connection('network')
        subnet = self._instance_subnet(instance)

        dest = '{}/32'.format(address)
        addr = Cidr(dest) # validate
        ipcfg_name = '{}-{}'.format(self.name(instance), addr.address.replace('.', '-')) # XXX this is a convention
        new_ip = {
            'properties': {
                'subnet': {'id': subnet.id},
                'privateIPAllocationMethod': 'static',
                'privateIPAddress': address,
            },
            'name': ipcfg_name,
        }

        # address must ber in subnet range since we use IP configurations
        if not Cidr(subnet.address_prefix).contains(address):
            raise vFXTConfigurationException("Address {} is does not fall within subnet {}".format(address, subnet.name))

        # check for existing
        existing_nic = self._nic_from_ip(address)
        if existing_nic:
            if not options.get('allow_reassignment', True):
                raise vFXTConfigurationException("Address {} already assigned to {}".format(address, existing_nic.name))
            self._remove_address_from_nic(existing_nic, address)

        nic = self._instance_primary_nic(instance)
        nic_rsg = nic.id.split('/')[4]

        # last ditch check here if available
        network_rsg = nic.ip_configurations[0].subnet.id.split('/')[4]
        network_name = nic.ip_configurations[0].subnet.id.split('/')[8]
        retries = self.NIC_OPERATIONS_RETRY
        while True:
            try:
                # TODO, when InUseByResource is included in the response inspect it for which nic the backend
                # believes is still holding the ip configuration.
                check = conn.virtual_networks.check_ip_address_availability(network_rsg, network_name, address)
                if check.available:
                    break
                if check.available is None: # call failed b/c no virtualNetwork/read permissions
                    break
                log.warn("Waiting for {} to show up via check_ip_address_availability".format(address))
            # permission denied, we can't use this check
            except msrestazure.azure_exceptions.CloudError:
                break
            except Exception as e:
                log.debug("Failed to check check_ip_address_availability for {}: {}".format(address, e))
            if retries == 0:
                raise vFXTServiceFailure("Address {} is not associated with any network interface but is not available".format(address))
            time.sleep(self.POLLTIME)
            retries -= 1

        retries = self.NIC_OPERATIONS_RETRY
        while True:
            nic_data = nic.serialize()
            nic_data['properties']['ipConfigurations'].append(new_ip)
            try:
                op = conn.network_interfaces.create_or_update(nic_rsg, nic.name, nic_data)
                self._wait_for_operation(op, retries=self.WAIT_FOR_IPCONFIG, msg='{} to be assigned to {}'.format(address, nic.name))
                break
            # check for retry-able/fatal exceptions
            except (msrestazure.azure_exceptions.CloudError, vFXTServiceFailure) as e:
                nic = self._instance_primary_nic(instance) # refresh on error
                log.debug("Failed to add address {} to {}: {}".format(address, self.name(instance), e))
                if retries == 0:
                    raise vFXTServiceFailure("Exceeded retries when adding address {} to {}: {}".format(address, self.name(instance), e))
            except (vFXTServiceTimeout, Exception) as e:
                raise vFXTServiceFailure("Failed to add address {} to {}: {}".format(address, self.name(instance), e))
            time.sleep(self.POLLTIME)
            retries -= 1

    def remove_instance_address(self, instance, address):
        '''Remove an instance address

            Arguments:
                instance: backend instance
                address (str): IP address

            Raises: vFXTServiceFailure
        '''
        if address not in self.instance_in_use_addresses(instance):
            raise vFXTConfigurationException("{} is not assigned to {}".format(address, self.name(instance)))
        if address == self.ip(instance):
            raise vFXTConfigurationException("The primary address {} can not be removed from {}".format(address, self.name(instance)))

        # address must be in subnet range since we use IP configurations
        subnet = self._instance_subnet(instance)
        if not Cidr(subnet.address_prefix).contains(address):
            raise vFXTConfigurationException("Address {} is does not fall within subnet {}".format(address, subnet.name))

        nic = self._instance_primary_nic(instance)
        return self._remove_address_from_nic(nic, address)

    def _remove_address_from_nic(self, nic, address):
        conn = self.connection('network')
        nic_rsg = nic.id.split('/')[4]

        retries = self.NIC_OPERATIONS_RETRY
        while True:
            nic_data = nic.serialize()
            nic_data['properties']['ipConfigurations'] = [_ for _ in nic_data['properties']['ipConfigurations'] if _['properties']['privateIPAddress'] != address]

            try:
                op = conn.network_interfaces.create_or_update(nic_rsg, nic.name, nic_data)
                self._wait_for_operation(op, retries=self.WAIT_FOR_IPCONFIG, msg='{} to be removed from {}'.format(address, nic.name))
                break
            # check for retry-able/fatal exceptions
            except (msrestazure.azure_exceptions.CloudError, vFXTServiceFailure) as e:
                nic = conn.network_interfaces.get(nic_rsg, nic.name) # refresh on error
                log.debug("Failed to remove address {} from {}: {}".format(address, nic.name, e))
                if retries == 0:
                    raise vFXTServiceFailure("Exceeded retries when removing address {} from {}: {}".format(address, nic.name, e))
            except (vFXTServiceTimeout, Exception) as e:
                raise vFXTServiceFailure("Failed to remove address {} from {}: {}".format(address, nic.name, e))
            time.sleep(self.POLLTIME)
            retries -= 1

    def in_use_addresses(self, cidr_block, **options): #pylint: disable=unused-argument
        '''Return a list of in use addresses within the specified cidr

            Arguments:
                cidr_block (str)
                resource_group (str, optional): network resource group
        '''
        conn        = self.connection('network')
        c           = Cidr(cidr_block)
        addresses   = set()

        for nic in conn.network_interfaces.list_all():
            for ip_config in nic.ip_configurations:
                addr = ip_config.private_ip_address
                if c.contains(addr):
                    addresses.add(addr)

        try:
            for rt in conn.route_tables.list_all(): # all resource groups
                for route in rt.routes:
                    if route.next_hop_type != 'VirtualAppliance':
                        continue
                    addr = Cidr(route.address_prefix).address
                    if c.contains(addr):
                        addresses.add(addr)
        except Exception as e:
            log.debug("Ignoring route lookup failure: {}".format(e))

        try:
            for gw in conn.application_gateways.list_all():
                for ipconfig in gw.frontend_ip_configurations:
                    addr = ipconfig.private_ip_address
                    if addr and c.contains(addr):
                        addresses.add(addr)
        except Exception as e:
            log.debug("Ignoring application gateway lookup failure: {}".format(e))

        try:
            for lb in conn.load_balancers.list_all():
                for ipconfig in lb.frontend_ip_configurations:
                    addr = ipconfig.private_ip_address
                    if addr and c.contains(addr):
                        addresses.add(addr)
        except Exception as e:
            log.debug("Ignoring load balancer lookup failure: {}".format(e))

        try:
            for ss in self.connection('compute').virtual_machine_scale_sets.list_all():
                ss_rg = ss.id.split('/')[4]
                for nic in conn.network_interfaces.list_virtual_machine_scale_set_network_interfaces(ss_rg, ss.name):
                    for ipconfig in nic.ip_configurations:
                        addr = ipconfig.private_ip_address
                        if addr and c.contains(addr):
                            addresses.add(addr)
        except Exception as e:
            log.debug('Ignoring scale set lookup failure: {}'.format(e))

        return list(addresses)

    def _nic_from_ip(self, address):
        netconn = self.connection('network')
        for nic in netconn.network_interfaces.list_all():
            for ipconfig in nic.ip_configurations:
                if address == ipconfig.private_ip_address:
                    return nic
        return None

    def _who_has_ip(self, address):
        nic = self._nic_from_ip(address)
        if nic and nic.virtual_machine:
            return self.get_instance(nic.virtual_machine.id.split('/')[-1])
        return None

    def instance_in_use_addresses(self, instance, category='all'):
        '''Get the in use addresses for the instance

            Arguments:
                instance (dict)
                category (str): all, instance, routes

            To obtain the public instance address, use 'public' category.  This
            is not included with 'all'.
        '''
        addresses = set()
        conn = self.connection('network')

        for iface in instance.network_profile.network_interfaces:
            iface_id = iface.id
            iface_name = iface_id.split('/')[-1]
            interface_resource_group = iface_id.split('/')[4] # use the instances nic resource_group
            interface = conn.network_interfaces.get(interface_resource_group, iface_name)
            for ipconfig in interface.ip_configurations:
                if category in ['all', 'instance']:
                    addresses.add(ipconfig.private_ip_address)
                if category in ['public']:
                    if ipconfig.public_ip_address:
                        pia_name = ipconfig.public_ip_address.id.split('/')[-1]
                        pia_rg = ipconfig.public_ip_address.id.split('/')[4]
                        pia = conn.public_ip_addresses.get(pia_rg, pia_name)
                        addresses.add(pia.ip_address)

        if category in ['all', 'routes']:
            primary_ip = self.ip(instance)
            subnet = self._instance_subnet(instance)
            if subnet.route_table:
                try:
                    network_resource_group = subnet.id.split('/')[4] # XXX no subnet.resource_group
                    rt = conn.route_tables.get(network_resource_group, subnet.route_table.id.split('/')[-1])
                    for route in rt.routes:
                        if route.next_hop_type != 'VirtualAppliance':
                            continue
                        if route.next_hop_ip_address == primary_ip:
                            addresses.add(Cidr(route.address_prefix).address)
                except Exception as e:
                    log.debug('Ignoring route table lookup failure: {}'.format(e))

        return list(addresses)

    def export(self):
        '''Export the service object in an easy to serialize format
            Returns:
                {}: serializable dictionary
        '''
        attrs = [
            'subscription_id',
            'application_id',
            'application_secret',
            'tenant_id',
            'resource_group',
            'storage_account',
            'location',
            'network',
            'proxy_uri',
            'private_range',
            'network_security_group',
            'endpoint_base_url',
            'storage_suffix',
        ]

        data = {}
        for attr in attrs:
            val = getattr(self, attr)
            if val:
                data[attr] = val
        if self.network_resource_group != self.resource_group:
            data['network_resource_group'] = self.network_resource_group
        if self.storage_resource_group != self.resource_group:
            data['storage_resource_group'] = self.storage_resource_group
        if self.use_environment_for_auth:
            data['use_environment_for_auth'] = self.use_environment_for_auth
            data['access_token'] = self.connection().config.credentials._token_retriever() # XXX?
        if self.on_instance:
            try:
                data['access_token'] = self.local.instance_data['access_token']
                data['on_instance'] = True
            except Exception: pass
        if self.subnets:
            data['subnet'] = self.subnets
        return data

    def valid_containername(self, name):
        '''Validate the container name

            Returns: bool
        '''
        # https://docs.microsoft.com/en-us/azure/architecture/best-practices/naming-conventions
        if len(name) > 63 or len(name) < 3:
            return False
        if not self.CONTAINER_NAME_RE.match(name):
            return False
        return True

    # alias for api compatibility
    valid_bucketname = valid_containername

    def valid_instancename(self, name):
        '''Validate the instance name

            Returns: bool
        '''
        # https://docs.microsoft.com/en-us/azure/architecture/best-practices/naming-conventions
        if not ServiceBase.valid_instancename(self, name):
            return False
        if len(name) > 64 or len(name) < 1:
            return False
        if self.INSTANCENAME_RE.match(name):
            return True
        return False

    def _copy_blob(self, src, dest_blob, container=None, storage_account=None, timeout=ServiceBase.WAIT_FOR_SERVICE_CHECKS):
        '''
            Copy a blob from a source URL to a local blob

            Arguments:
                src (str): the source URL of the blob (typically Avere SAS image)
                dest_blob (str): blob name
                container (str): container for the destination blob
                storage_account (str, optional): the storage account to use
                timeout (int, optional): timeout for the copy operation
        '''
        container = container or self.SYSTEM_CONTAINER
        log.debug("Copying {} to {} in container {}".format(src, dest_blob, container))
        storage_account = storage_account or self.storage_account

        blob_srv = self.connection('blobstorage', storage_account=storage_account)

        if container not in [_.name for _ in blob_srv.list_containers()]:
            rv = blob_srv.create_container(container)
            if not rv:
                raise vFXTServiceFailure("Failed to create container {}".format(container))

        stall_count = 0
        last_progress = None
        rate_limit = 0
        copy_op = blob_srv.copy_blob(container, dest_blob, src)
        while copy_op.status != 'success':
            if not rate_limit % 10:
                log.debug("copy {} {}: {}".format(dest_blob, copy_op.status, copy_op.progress or 'starting'))

            try:
                blob_prop = blob_srv.get_blob_properties(container, dest_blob)
                copy_op = blob_prop.properties.copy
            except Exception as e:
                log.error("Failed to get blob properties for {}: {}".format(dest_blob, e))
                raise

            # check for stalled
            if last_progress == copy_op.status:
                stall_count += 1
            else:
                stall_count = 0
                last_progress = copy_op.status
            if stall_count == timeout:
                raise vFXTServiceTimeout("Failed waiting for {} to copy".format(dest_blob))

            rate_limit += 1
            time.sleep(self.POLLTIME)

    def _create_nic(self, name, network=None, subnet=None, resource_group=None,
                    location=None, private_address=None, enable_ip_forwarding=False, network_security_group=None,
                    enable_public_address=False, advanced_networking=False):
        '''Create a nic
        '''
        conn = self.connection('network')
        network = network or self.network
        subnet = subnet or self.subnets[0]
        location = location or self.location
        resource_group = resource_group or self.resource_group

        # Note that we create the NIC in the compute resource group, NOT the
        # network resource group.  The subnet/vnet are assumed to be in the
        # network resource group (if different from the vm/compute resource
        # group)

        data = {
            'location': location,
            'enable_ip_forwarding': enable_ip_forwarding,
            'enable_accelerated_networking': advanced_networking,
            'ip_configurations': [
                {
                    'name': 'ipconfig-{}-{}'.format(name, int(time.time())),
                    'subnet': {'id': self._subnet_scope(network, subnet)},
                }
            ]
        }

        if private_address:
            data['ip_configurations'][0]['private_ip_allocation_method'] = 'Static'
            data['ip_configurations'][0]['private_ip_address'] = private_address
        else:
            data['ip_configurations'][0]['private_ip_allocation_method'] = 'Dynamic'

        if enable_public_address:
            try:
                body = {
                    'location': self.location,
                    'public_ip_allocation_method': 'Dynamic'
                }
                log.debug("Creating public ip address {}-public-address: {}".format(name, body))
                op = conn.public_ip_addresses.create_or_update(resource_group, '{}-public-address'.format(name), body)
                self._wait_for_operation(op, msg='IP address to be created')

                public_address = conn.public_ip_addresses.get(resource_group, '{}-public-address'.format(name))
                log.info("Created {}-public-address".format(name))
                data['ip_configurations'][0]['public_ip_address'] = {'id': public_address.id}
            except Exception as e:
                log.error("Failed to create {}-public-address: {}".format(name, e))
                raise

        if network_security_group:
            data['network_security_group'] = {'id': self._network_security_group_scope(network_security_group)}

        log.debug("Creating network interface {}: {}".format(name,data))
        op = conn.network_interfaces.create_or_update(resource_group, name, data)
        self._wait_for_operation(op, retries=self.WAIT_FOR_NIC, msg='network interface {} to be created'.format(name))
        log.info("Created network interface {}".format(name))
        return conn.network_interfaces.get(resource_group, name)

    def _delete_nic(self, name, resource_group=None):
        netconn = self.connection('network')
        resource_group = resource_group or self.resource_group

        nic = netconn.network_interfaces.get(resource_group, name)
        op = netconn.network_interfaces.delete(resource_group, name)
        self._wait_for_operation(op, retries=self.WAIT_FOR_NIC, msg='network interface {} to be deleted'.format(name))

        # if a public address is associated
        for public_addr in [config.public_ip_address.id.split('/')[-1] for config in nic.ip_configurations if config.public_ip_address]:
            op = netconn.public_ip_addresses.delete(resource_group, public_addr)
            # skip self._wait_for_operation(op, msg='public address {} to be deleted'.format(public_addr))

        # clean up routes pointing to this nic
        primary_ip = nic.ip_configurations[0].private_ip_address
        try:
            for rt in netconn.route_tables.list_all():
                for route in rt.routes:
                    if route.next_hop_type != 'VirtualAppliance':
                        continue
                    if route.next_hop_ip_address != primary_ip:
                        continue
                    try:
                        route_rg = route.id.split('/')[4]
                        table_name = route.id.split('/')[-3]
                        route_name = route.id.split('/')[-1]
                        op = netconn.routes.delete(route_rg, route_table_name=table_name, route_name=route_name)
                        # skip self._wait_for_operation(op, msg='route to be deleted')
                    except Exception as route_del_e:
                        log.error("Failed to delete route for nic {}: {}".format(name, route_del_e))
        except Exception as e:
            log.error("Failed to clean up routes for nic {}: {}".format(name, e))

    def _create_role(self, name, **options):
        '''Create an Azure role

            Arguments:
                name (str): role name
                permissions ([{}]): permissions for role (defaults to vFXT.msazure.ROLE_PERMISSIONS)

            Returns
                role dictionary

            Raises: vFXTServiceFailure
        '''
        conn = self.connection('authorization')

        role_id     = str(uuid.uuid4())
        permissions = options.get('permissions') or self.ROLE_PERMISSIONS

        body = {
            'type': 'CustomRole',
            'role_name': name,
            'description': 'Automatically created for Avere {}'.format(name),
            'permissions': permissions,
            'assignable_scopes': [self._resource_group_scope()],
        }
        if self.network_resource_group != self.resource_group:
            body['assignable_scopes'].append(self._network_resource_group_scope())

        retries = options.get('retries') or ServiceBase.CLOUD_API_RETRIES
        while True:
            try:
                r = conn.role_definitions.create_or_update(self._resource_group_scope(), role_id, body)
                if not r:
                    raise Exception("Failed to create role {}".format(name))
                log.debug("Created role {} with body {}".format(r.id, body))
                return r
            except Exception as e:
                log.debug(e)

                # check if it already exists, if so we reuse that ID and update the definition on
                # retry
                try:
                    existing = self._get_role(name, retries=1)
                    role_id = existing.id.split('/')[-1]
                    log.warn("Role {} exists with id {}, updating the definition".format(name, role_id))
                except vFXTConfigurationException: pass

                time.sleep(self.POLLTIME)
                if retries == 0:
                    raise vFXTServiceFailure("Failed to create role {}: {}".format(name, e))
            retries -= 1

    def _get_role(self, role_name, retries=ServiceBase.CLOUD_API_RETRIES):
        '''Retrieve a role
        '''
        # may need to retry if it was recently created
        while True:
            conn = self.connection('authorization')
            try:
                roles = [_ for _ in conn.role_definitions.list(self._subscription_scope()) if role_name == _.role_name]
                if roles and roles[0]:
                    return roles[0]
                raise Exception("No such role: {}".format(role_name))
            except Exception as e:
                log.debug(e)
                time.sleep(self.POLLTIME)
                if retries == 0:
                    raise vFXTConfigurationException("Role {} not found".format(role_name))
                log.warn("Failed to lookup role {}, retrying".format(role_name))
            retries -= 1

    def _delete_role(self, role_name):
        '''Delete an Azure role

            Arguments:
                role_name (str): role name

            Raises: vFXTServiceFailure
        '''
        conn = self.connection('authorization')

        role = self._get_role(role_name)
        if not role:
            raise vFXTConfigurationException("No such role: {}".format(role_name))
        try:
            # must delete assignments first
            assignments = [_ for _ in conn.role_assignments.list() if role.id == _.role_definition_id]
            for assignment in assignments:
                # this will fail if we do not have permissions
                conn.role_assignments.delete(assignment.scope, assignment.name)

            # this will fail if we do not have permissions
            conn.role_definitions.delete(self._resource_group_scope(), role.id)
        except Exception as e:
            log.debug(e)
            raise vFXTServiceFailure("Failed to delete role {}: {}".format(role_name, e))

    def _assign_role(self, principal, role_name, **options):
        '''Assign a role to a service principal

            Arguments:
                principal (str): principal ID
                role_name (str): name to use

            Raises: vFXTServiceFailure
        '''
        retries = options.get('retries') or self.NEW_ROLE_FETCH_RETRY

        role = self._get_role(role_name, retries=retries)
        if not role:
            raise vFXTServiceFailure("Failed to find role {}".format(role_name))

        while True:
            association_id = str(uuid.uuid4())
            try:
                conn = self.connection('authorization')
                assignments = [_ for _ in conn.role_assignments.list() if role.id == _.role_definition_id]
                if principal in [_.principal_id for _ in assignments]:
                    log.debug("Assignment for role {} and principal {} exists.".format(role.role_name, principal))
                    return None

                body = {
                    'role_definition_id': role.id,
                    'principal_id': principal
                }

                scope = self._resource_group_scope()
                r = conn.role_assignments.create(scope, association_id, body)
                if not r:
                    raise Exception("Failed to assign role {} to principal {} for resource group {}".format(role_name, principal, self.resource_group))
                log.debug("Assigned role {} with principal {} to scope {}: {}".format(role_name, principal, scope, body))
                # if we span resource groups, the scope must be assigned to both resource groups
                if self.network_resource_group != self.resource_group:
                    network_scope = self._resource_group_scope(self.network_resource_group)
                    network_association_id = str(uuid.uuid4())
                    r2 = conn.role_assignments.create(network_scope, network_association_id, body)
                    if not r2:
                        raise Exception("Failed to assign role {} to principal {} for resource group {}".format(role_name, principal, self.network_resource_group))
                return r
            except Exception as e:
                log.debug(e)
                if retries == 0:
                    raise vFXTServiceFailure("Failed to assign role {}: {}".format(role_name, e))
                log.warn("Failed to assign role {} to principal {}, retrying".format(role_name, principal))
                time.sleep(self.POLLTIME)
            retries -= 1

    def _create_availability_set(self, name, **options):
        '''Create an availability set

            Arguments:
                name (str): availability set name
                location (str, optional): location for availability set

            Raises: vFXTServiceFailure
        '''
        conn = self.connection()

        location = options.get('location') or self.location
        fault_domain_count = 3 if location in self.REGIONS_WITH_3_FAULT_DOMAINS else 2

        body = {
            'location': location,
            'platform_fault_domain_count': fault_domain_count,
            'platform_update_domain_count': self.MAX_UPDATE_DOMAIN_COUNT,
            'sku': {'name': 'aligned'},
        }
        try:
            log.info('Creating cluster availability set {}'.format(name))
            log.debug("Availability set config: {}".format(body))
            return conn.availability_sets.create_or_update(self.resource_group, name, body)
        except Exception as e:
            raise vFXTServiceFailure("Failed to create availability set {}: {}".format(name, e))

    def _delete_availability_set(self, name):
        '''Delete an availability set

            Arguments:
                name (str): availability set name

            Raises: vFXTServiceFailure
        '''
        conn = self.connection()
        try:
            conn.availability_sets.delete(self.resource_group, name)
            log.debug("Deleted availability set {}".format(name))
        except Exception as e:
            raise vFXTServiceFailure("Failed to delete availability set {}: {}".format(name, e))

    def _location_names(self):
        '''Get a list of location names
            Returns: list
        '''
        return [_.name for _ in self.connection('subscription').subscriptions.list_locations(self.subscription_id)]

    def _parse_vhd_uri(self, vhd_uri):
        '''Parse the VHD URI

            Returns {'storage_account': '', 'container': '', 'blob': ''}
        '''
        parts = vhd_uri.split('/')
        storage_account = parts[2].split('.')[0]
        container = parts[3]
        blob = '/'.join(parts[4:])
        return {'storage_account': storage_account, 'container': container, 'blob': blob}

    @classmethod
    def _list_subscriptions(cls, tenant_id, application_id, application_secret, proxy_uri=None):
        '''Get a list of subscriptions tied to the client/tenant
            Arguments:
                tenant_id (str): AD application tenant identifier
                application_id (str): AD application ID
                application_secret (str): AD application secret
                proxy_uri (str, optional): URI of proxy resource (e.g. http://user:pass@172.16.16.20:8080)
        '''
        service = Service(subscription_id=None,
                            tenant_id=tenant_id,
                            application_id=application_id,
                            application_secret=application_secret,
                            proxy_uri=proxy_uri,
                            no_connection_test=True)
        return [_.subscription_id for _ in service.connection('subscription').subscriptions.list()]

    def _cache_to_disk_config(self, cache_size, machine_type=None, disk_type=None):#pylint: disable=unused-argument
        '''For a given cache size, output the default data disk count and size

            Arguments:
                cache_size (int): vFXT cluster node cache size in GB
                machine_type (str, optional): vFXT cluster node machine type
                disk_type (str, optional): vFXT cluster node disk type

            Returns:
                tuple (disk count, size per disk)
        '''
        sizes = sorted(self.VALID_DATA_DISK_SIZES, reverse=True)

        best_size = 0
        for sz in sizes:
            if cache_size < sz: continue
            if cache_size % sz == 0:
                best_size = sz
                break
        # If it wasn't a perfect multiple of one of the sizes, choose
        # the closest match and round up
        if not best_size:
            for i in reversed(range(len(sizes))):
                if cache_size <= sizes[i]:
                    best_size = sizes[i]
                    break
        # If the cache is bigger than the biggest disk, just use the
        # big disks.
        if not best_size:
            best_size = sizes[0]

        size = best_size

        if cache_size >= 256 and cache_size <= 1024:
            size = 256
        # better to use 512GB disks if possible, up to a point
        elif cache_size > 1024 and cache_size <= 4096:
            size = 512
        elif cache_size > 4096 and cache_size <= 8192:
            size = 1024

        count = int((cache_size+size-1) / size)
        return tuple([count, size])

    def _get_network(self, network=None, resource_group=None):
        '''Return the current network
        '''
        resource_group = resource_group or self.network_resource_group
        network = network or self.network
        return self.connection('network').virtual_networks.get(resource_group, network)

    def _list_storage_accounts(self):
        '''Return a list of storage accounts
        '''
        return list(self.connection('storage').storage_accounts.list())

    def _get_default_image(self):
        '''Get the default image from the defaults
        '''
        return self.DEFAULT_MARKETPLACE_URN

    def _subscription_scope(self):
        return '/subscriptions/{}'.format(self.subscription_id)

    def _resource_group_scope(self, resource_group=None):
        resource_group = resource_group or self.resource_group
        return '{}/ResourceGroups/{}'.format(self._subscription_scope(), resource_group)
    def _network_resource_group_scope(self, resource_group=None):
        resource_group = resource_group or self.network_resource_group
        return '{}/ResourceGroups/{}'.format(self._subscription_scope(), resource_group)

    def _subnet_scope(self, network, subnet):
        return '{}/providers/Microsoft.Network/virtualNetworks/{}/subnets/{}'.format(self._network_resource_group_scope(), network, subnet)

    def _network_security_group_scope(self, name):
        return '{}/providers/Microsoft.Network/networkSecurityGroups/{}'.format(self._network_resource_group_scope(), name)

    def _blob_exists(self, storage_account, container, blob):
        log.debug("Checking if blob {} exists in {}/{}".format(blob, storage_account, container))
        blob_srv = self.connection('blobstorage', storage_account=storage_account)

        try:
            rv = blob_srv.get_blob_properties(container, blob)
            if not rv:
                return False
            return True
        except Exception:
            return False

    def _delete_blob(self, storage_account, container, blob):
        blob_srv = self.connection('blobstorage', storage_account=storage_account)
        log.debug("Deleting blob {}/{} from storage account {}".format(container, blob, storage_account))
        try:
            blob_srv.delete_blob(container, blob, delete_snapshots='Include')
        except Exception:
            raise

    def _create_image_from_vhd(self, vhd_url, name=None, caching='None'):
        '''Create a local image from a remove vhd url
        '''
        conn = self.connection()

        if caching not in self.VALID_CACHING_OPTIONS:
            raise vFXTConfigurationException("Invalid caching value: {}".format(caching))

        url = urlparse.urlparse(vhd_url)
        if not all([url.hostname, url.path]):
            raise vFXTConfigurationException("Invalid VHD url: {}".format(vhd_url))

        name = name or url.path.split('/')[-1].replace('.vhd', '')
        try:
            img = conn.images.get(self.resource_group, name)
            if img.location == self.location:
                return img
            name = '{}-{}'.format(name, self.location)
        except Exception:
            pass

        params = {
            'location': self.location,
            'storage_profile': {
                'os_disk': {
                    'os_type': 'Linux',
                    'os_state': 'Generalized',
                    'caching': caching,
                    'blob_uri': vhd_url,
                    'storage_account_type': self.DEFAULT_STORAGE_ACCOUNT_TYPE,
                }
            }
        }

        log.debug("Creating image {} with parameters {}".format(name, params))
        op = conn.images.create_or_update(self.resource_group, name, params)
        self._wait_for_operation(op, msg='image to be created')
        return conn.images.get(self.resource_group, name)

    def _cidr_overlaps_network(self, cidr_range):
        cidr = Cidr(cidr_range)
        network = self._get_network()
        for address_prefix in [subnet.address_prefix for subnet in network.subnets]:
            address_cidr = Cidr(address_prefix)
            if address_cidr.contains(cidr.start_address()):
                return True
        return False
