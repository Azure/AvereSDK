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
import unittest

from vFXT.aws import Service as AWS
from vFXT.gce import Service as GCE


class Base(unittest.TestCase):
    def setUp(self):
        '''Load the test_config.json file which has our required test options'''
        try:
            import json
            f = open('tests/test_config.json', 'r')
            test_config = json.load(f)
            self.create_clusters                = test_config['create_clusters']
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

        except Exception as e:
            self.skipTest(e)

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
        key_file        = self.gce['key_file']
        private_range   = self.gce['private_range']
        return GCE(client_email=client_email, key_file=key_file, zone=zone_id, project_id=project_id, network_id=network_id, private_range=private_range)


