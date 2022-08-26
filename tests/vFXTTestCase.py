# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
import json
import unittest
import warnings

from vFXT.msazure import Service as Azure


class Base(unittest.TestCase):
    def setUp(self):
        '''Load the test_config.json file which has our required test options'''
        try:
            with open('tests/test_config.json') as f:
                test_config = json.load(f)
            self.create_clusters                = test_config['create_clusters']
            self.shelve                         = test_config.get('shelve')
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
            self.azure['storage_account']               = test_config['azure']['storage_account']
            self.azure['instance_type']                 = test_config['azure']['instance_type']
            self.azure['existing']                      = test_config['azure']['existing_instances']
            self.azure['image']                         = test_config['azure']['image']
            self.azure['vfxt_image']                    = test_config['azure']['vfxt_image']
            self.azure['check_on_instance']             = test_config['azure']['check_on_instance']
            self.azure['check_from_environment']        = test_config['azure']['check_from_environment']
        except Exception as e:
            self.skipTest(e)

        try:
            warnings.filterwarnings(action="ignore", message="unclosed", category=ResourceWarning)
        except NameError:
            pass

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
