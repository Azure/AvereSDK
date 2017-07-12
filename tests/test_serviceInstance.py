#!/usr/bin/python
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
import logging
import uuid

from vFXT.serviceInstance import ServiceInstance
import vFXT.service
import tests.vFXTTestCase

logging.basicConfig()

class ServiceInstance_test(tests.vFXTTestCase.Base):

    def test__init__aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")

        aws = self.mk_aws_service()
        si = ServiceInstance(aws, self.aws['existing'][0])
        self.assertIsInstance(si, ServiceInstance)
        self.assertTrue(si.instance_id == self.aws['existing'][0])
        self.assertTrue(si.ip() != '')
        self.assertTrue(si.id() != '')
        self.assertTrue(si.name() != '')
        self.assertTrue(si.fqdn() != '')
        self.assertTrue(si.status() != '')
        self.assertTrue(si.is_on())
        self.assertFalse(si.is_off())
        self.assertFalse(si.refresh())
        self.assertTrue(len(si.in_use_addresses())>0)
        self.assertTrue(ServiceInstance(aws, instance=si.instance))
        self.assertRaises(Exception, ServiceInstance, aws, str(uuid.uuid4()))

    def test__init__gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")

        gce = self.mk_gce_service()
        si = ServiceInstance(gce, self.gce['existing'][0])
        self.assertIsInstance(si, ServiceInstance)
        self.assertTrue(si.instance_id == self.gce['existing'][0])
        self.assertTrue(si.ip() != '')
        self.assertTrue(si.id() != '')
        self.assertTrue(si.name() != '')
        self.assertTrue(si.fqdn() != '')
        self.assertTrue(si.status() != '')
        self.assertTrue(si.is_on())
        self.assertFalse(si.is_off())
        self.assertFalse(si.refresh())
        self.assertTrue(len(si.in_use_addresses())>0)
        self.assertTrue(ServiceInstance(gce, instance=si.instance))
        self.assertRaises(vFXT.service.vFXTConfigurationException, ServiceInstance, gce, str(uuid.uuid4()))

    def test_bad_instance_aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")

        aws = self.mk_aws_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, ServiceInstance,aws, instance=None)

    def test_bad_instance_gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")

        gce = self.mk_gce_service()
        invalid_gce_instance = ServiceInstance(gce, instance={'name': str(uuid.uuid4())})
        self.assertRaises(vFXT.service.vFXTConfigurationException, invalid_gce_instance.refresh)


if __name__ == '__main__':
    unittest.main()
