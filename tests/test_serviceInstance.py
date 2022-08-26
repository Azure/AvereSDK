#!/usr/bin/python
# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
import unittest
import logging
import uuid

from vFXT.serviceInstance import ServiceInstance
import vFXT.service
import tests.vFXTTestCase

logging.basicConfig()

class ServiceInstance_test(tests.vFXTTestCase.Base):

    def test__init__azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")

        azure = self.mk_azure_service()
        si = ServiceInstance(azure, self.azure['existing'][0])
        self.assertIsInstance(si, ServiceInstance)
        self.assertTrue(si.instance_id == self.azure['existing'][0])
        self.assertTrue(si.ip() != '')
        self.assertTrue(si.id() != '')
        self.assertTrue(si.name() != '')
        self.assertTrue(si.fqdn() != '')
        self.assertTrue(si.status() != '')
        self.assertFalse(si.refresh())
        self.assertTrue(len(si.in_use_addresses())>0)
        self.assertTrue(ServiceInstance(azure, instance=si.instance))
        self.assertRaises(vFXT.service.vFXTConfigurationException, ServiceInstance, azure, str(uuid.uuid4()))

    def test_bad_instance_azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")

        azure = self.mk_azure_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, ServiceInstance, azure, str(uuid.uuid4()))


if __name__ == '__main__':
    unittest.main()
