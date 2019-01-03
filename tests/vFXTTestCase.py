# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
import unittest
import warnings

from vFXT.aws import Service as AWS
from vFXT.gce import Service as GCE
from vFXT.msazure import Service as Azure


class Base(unittest.TestCase):
    def setUp(self):
        '''Load the test_config.json file which has our required test options'''
        try:
            import json
            f = open('tests/test_config.json', 'rb')
            test_config = json.load(f)
            self.create_clusters                = test_config['create_clusters']
            self.shelve                         = test_config.get('shelve')
            self.gce = {}                       # gce options
            self.gce['enabled']                 = test_config['gce']['enabled']
            self.gce['client_email']            = test_config['gce']['client_email']
            self.gce['key_file']                = test_config['gce']['key_file']
            self.gce['project_id']              = test_config['gce']['project_id']
            self.gce['zone_id']                 = test_config['gce']['zone_id']
            self.gce['zones']                   = test_config['gce']['zones']
            self.gce['network_id']              = test_config['gce']['network_id']
            self.gce['subnetwork_id']           = test_config['gce']['subnetwork_id']
            self.gce['image']                   = test_config['gce']['image']
            self.gce['instance_type']           = test_config['gce']['instance_type']
            self.gce['existing']                = test_config['gce']['existing_instances']
            self.gce['bucket']                  = test_config['gce']['bucket']
            self.gce['bucket_file']             = test_config['gce']['bucket_file']
            self.gce['vfxt_image']              = test_config['gce']['vfxt_image']
            self.gce['check_on_instance']       = test_config['gce']['check_on_instance']
            self.gce['check_from_environment']  = test_config['gce']['check_from_environment']
            self.gce['private_range']           = test_config['gce']['private_range']
            self.aws = {}                       # aws options
            self.aws['enabled']                 = test_config['aws']['enabled']
            self.aws['access_key']              = test_config['aws']['access_key']
            self.aws['secret_access_key']       = test_config['aws']['secret_access_key']
            self.aws['s3_access_key']           = test_config['aws'].get('s3_access_key', self.aws['access_key'])
            self.aws['s3_secret_access_key']    = test_config['aws'].get('s3_secret_access_key', self.aws['secret_access_key'])
            self.aws['region']                  = test_config['aws']['region']
            self.aws['subnet']                  = test_config['aws']['subnet']
            self.aws['subnets']                 = test_config['aws']['subnets']
            self.aws['ami']                     = test_config['aws']['ami']
            self.aws['instance_type']           = test_config['aws']['instance_type']
            self.aws['existing']                = test_config['aws']['existing_instances']
            self.aws['vfxt_image']              = test_config['aws']['vfxt_image']
            self.aws['check_on_instance']       = test_config['aws']['check_on_instance']
            self.aws['check_from_environment']  = test_config['aws']['check_from_environment']
            self.azure = {}                             # azure options
            self.azure['enabled']                       = test_config['azure']['enabled']
            self.azure['subscription_id']               = test_config['azure']['subscription_id']
            self.azure['application_id']                = test_config['azure']['application_id']
            self.azure['application_secret']            = test_config['azure']['application_secret']
            self.azure['tenant_id']                     = test_config['azure']['tenant_id']
            self.azure['storage_resource_group']        = test_config['azure']['storage_resource_group']
            self.azure['network_resource_group']        = test_config['azure']['network_resource_group']
            self.azure['resource_group']                = test_config['azure']['resource_group']
            self.azure['location']                      = test_config['azure']['location']
            self.azure['network']                       = test_config['azure']['network']
            self.azure['subnet']                        = test_config['azure']['subnet']
            self.azure['role']                          = test_config['azure']['role']
            self.azure['storage_account']               = test_config['azure']['storage_account']
            self.azure['instance_type']                 = test_config['azure']['instance_type']
            self.azure['existing']                      = test_config['azure']['existing_instances']
            self.azure['image']                         = test_config['azure']['image']
            self.azure['vfxt_image']                    = test_config['azure']['vfxt_image']
            self.azure['check_on_instance']             = test_config['azure']['check_on_instance']
            self.azure['check_from_environment']        = test_config['azure']['check_from_environment']

            f.close()

        except Exception as e:
            self.skipTest(e)

        try:
            warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
        except NameError:
            pass

    def mk_aws_service(self):
        service = AWS(
            region=self.aws['region'],
            access_key=self.aws['access_key'],
            secret_access_key=self.aws['secret_access_key'],
            s3_access_key=self.aws['s3_access_key'],
            s3_secret_access_key=self.aws['s3_secret_access_key'],
            subnet=self.aws['subnet']
        )
        return service

    def mk_gce_service(self):
        client_email    = self.gce['client_email']
        project_id      = self.gce['project_id']
        zone_id         = self.gce['zone_id']
        network_id      = self.gce['network_id']
        subnetwork_id   = self.gce['subnetwork_id']
        key_file        = self.gce['key_file']
        private_range   = self.gce['private_range']
        return GCE(client_email=client_email, key_file=key_file, zone=zone_id, project_id=project_id, network_id=network_id, private_range=private_range, subnetwork_id=subnetwork_id)

    def mk_azure_service(self):
        service =  Azure(
            subscription_id=str(self.azure['subscription_id']), # WTF, TypeError("Parameter 'subscription_id' must be str.")
            application_id=self.azure['application_id'],
            application_secret=self.azure['application_secret'],
            tenant_id=self.azure['tenant_id'],
            storage_resource_group=self.azure['storage_resource_group'],
            network_resource_group=self.azure['network_resource_group'],
            resource_group=self.azure['resource_group'],
            location=self.azure['location'],
            network=self.azure['network'],
            subnet=self.azure['subnet'],
            storage_account=self.azure['storage_account'],
        )
        return service
