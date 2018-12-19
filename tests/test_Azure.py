#!/usr/bin/python
# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
import unittest
import time
import logging
import random
import uuid

import vFXT.service

from vFXT.msazure import Service
from vFXT.serviceInstance import ServiceInstance
import tests.vFXTTestCase

logging.basicConfig()
log = logging.getLogger(__name__)

class Azure_test(tests.vFXTTestCase.Base):
    def setUp(self):
        tests.vFXTTestCase.Base.setUp(self)
        if not self.azure['enabled']:
            self.skipTest("skipping tests for Azure")

    def test__init__(self):
        service = self.mk_azure_service()
        self.assertIsInstance(service, vFXT.msazure.Service)

    def test_from_environment_init(self):
        if not self.azure['check_from_environment']:
            self.skipTest("skipping check_from_environment test")
        service = Service.environment_init(
            subscription_id=str(self.azure['subscription_id']),
            application_id=self.azure['application_id'],
            application_secret=self.azure['application_secret'],
            tenant_id=self.azure['tenant_id'],
            resource_group=self.azure['resource_group'],
            location=self.azure['location'],
            network=self.azure['network'],
            subnet=self.azure['subnet']
        )
        self.assertIsInstance(service, vFXT.msazure.Service)

    def test_on_instance_init(self):
        if not self.azure['check_on_instance']:
            self.skipTest("skipping check_on_instance test")
        service = Service.on_instance_init(
            subscription_id=str(self.azure['subscription_id']),
            application_id=self.azure['application_id'],
            application_secret=self.azure['application_secret'],
            tenant_id=self.azure['tenant_id'],
            resource_group=self.azure['resource_group'],
            location=self.azure['location'],
            network=self.azure['network'],
            subnet=self.azure['subnet']
        )
        self.assertIsInstance(service, vFXT.msazure.Service)

    def test_connection(self):
        service = self.mk_azure_service()
        self.assertTrue(service)

    def test_find_instance(self):
        service = self.mk_azure_service()
        instances = service.find_instances()
        self.assertTrue(len(instances) > 0, msg="Assuming we always have instances")

    def test_get_instances(self):
        service = self.mk_azure_service()
        instances = service.get_instances(self.azure['existing'])
        self.assertTrue(len(instances) > 0, msg="Checking for our basic service instances")

    def test_get_instance(self):
        service = self.mk_azure_service()
        instance = service.get_instance(self.azure['existing'][0])
        self.assertTrue(instance)

    def test_invalid_instancename(self):
        service = self.mk_azure_service()
        invalid_name = 'this-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-namethis-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-namethis-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-namethis-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-name'
        self.assertRaises(vFXT.service.vFXTConfigurationException, ServiceInstance.create, service, self.azure['instance_type'], invalid_name, boot_disk_image=self.azure['image'])

        self.assertTrue(service.valid_instancename('vfxttest-lg-test'))
        self.assertFalse(service.valid_instancename('0vfxttest-lg-test'))
        self.assertFalse(service.valid_instancename('-vfxttest-lg-test'))
        self.assertFalse(service.valid_instancename('this-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-name'))

    def test_invalid_machinetype(self):
        service = self.mk_azure_service()
        name = 'vfxttest-lg-test-{}'.format(int(time.time()))
        self.assertRaises(vFXT.service.vFXTServiceFailure, ServiceInstance.create, service, 'invalid-machine-type', name, boot_disk_image=self.azure['image'])

    def test_create_instance(self):
        service = self.mk_azure_service()
        name = 'vfxttest-lg-test-{}'.format(int(time.time()))
        instance = ServiceInstance.create(service, self.azure['instance_type'], name, boot_disk_image=self.azure['image'], tags={'purpose':'vfxt-unittest-deleteme'}, user_data="this\nis\na\test")
        self.assertTrue(instance.instance.tags['purpose'] == 'vfxt-unittest-deleteme')

        try:
            self.assertTrue(instance.name())
            self.assertTrue(instance.id())
            self.assertTrue(instance.ip())
            self.assertTrue(instance.fqdn())
            self.assertTrue(instance.status())

            # use ip configurations for addresses within the subnet
            subnet = service._instance_subnet(instance.instance)
            addrs, _ = service.get_available_addresses(count=10, addr_range=subnet.address_prefix)
            addr = random.choice(addrs)
            instance.add_address(addr)
            instance.refresh()
            self.assertTrue(addr in instance.in_use_addresses())
            # duplicate failure
            self.assertRaises(vFXT.service.vFXTConfigurationException, instance.add_address, addr)
            instance.remove_address(addr)
            instance.refresh()
            self.assertFalse(addr in instance.in_use_addresses())

            self.assertTrue(instance.is_on())
            if service.can_stop(instance.instance):
                instance.stop()
                self.assertTrue(instance.is_off())
            if instance.is_off():
                instance.start()
                self.assertTrue(instance.is_on())
        except Exception as e:
            log.debug(e)
            raise
        finally:
            instance.destroy()

    def test_default_router(self):
        service = self.mk_azure_service()
        self.assertTrue(service.get_default_router(subnet_id=self.azure['subnet']))
        self.assertTrue(service.get_default_router())
    def test_default_dns(self):
        service = self.mk_azure_service()
        result = service.get_dns_servers()
        self.assertTrue(result)
        self.assertTrue(service.get_dns_servers() == result)
    def test_default_ntp(self):
        service = self.mk_azure_service()
        result = service.get_ntp_servers()
        self.assertTrue(result)
        self.assertTrue(service.get_ntp_servers() == result)

    def test_instance_in_use_addresses(self):
        service = self.mk_azure_service()
        instance = service.get_instance(self.azure['existing'][0]) # well known instance
        self.assertTrue(service.instance_in_use_addresses(instance))

    def test_export(self):
        service = self.mk_azure_service()
        d = service.export()
        s = Service(**d)
        d2 = s.export()
        self.assertDictEqual(d, d2)

    def test_refresh(self):
        service = self.mk_azure_service()
        instance = service.get_instance(self.azure['existing'][0])
        self.assertTrue(service.refresh(instance))

    def test_get_available_addresses(self):
        service = self.mk_azure_service()
        addresses = service.get_available_addresses()
        self.assertTrue(addresses)
        self.assertTrue(service.get_available_addresses(count=2))
        self.assertTrue(service.get_available_addresses(count=2, contiguous=False))

    def test_location_names(self):
        service = self.mk_azure_service()
        self.assertTrue(service._location_names())

    def test_availability_set(self):
        service = self.mk_azure_service()
        name = 'vfxttest-availability_set-test-{}'.format(int(time.time()))
        self.assertTrue(service._create_availability_set(name))
        service._delete_availability_set(name)

    def test_create_role(self):
        return self.skipTest("skipping _create_role") # no longer able to test in current environment
        #service = self.mk_azure_service()
        #name = 'vfxttest-role-{}'.format(int(time.time()))
        #self.assertTrue(service._create_role(name))
        #self.assertTrue(service._get_role(name))
        #try:
        #    service._delete_role(name)
        #except Exception as e:
        #    logging.warn("Ignoring failure to remove role in case of missing permissions: {}".format(e))

    def test_move_route(self):
        service = self.mk_azure_service()
        i1 = None
        i2 = None
        try:
            uniq = int(time.time())
            i1 = ServiceInstance.create(service, self.azure['instance_type'], 'vfxttest-dup-route-1-{}'.format(uniq), self.azure['image'])
            i2 = ServiceInstance.create(service, self.azure['instance_type'], 'vfxttest-dup-route-2-{}'.format(uniq), self.azure['image'])

            addrs, _ = service.get_available_addresses(count=30)
            addr = addrs[-1]
            i1.add_address(addr)
            i2.add_address(addr)
            i1.refresh()
            i2.refresh()
            self.assertTrue(addr not in i1.in_use_addresses())
            self.assertTrue(addr in i2.in_use_addresses())

        finally:
            if i1:
                try:
                    i1.destroy()
                except Exception as e:
                    log.debug(e)
            if i2:
                try:
                    i2.destroy()
                except Exception as e:
                    log.debug(e)

    def test_cache_to_disk_config(self):
        service = self.mk_azure_service()
        self.assertTrue(service._cache_to_disk_config(100) == (1, 128))
        self.assertTrue(service._cache_to_disk_config(250) == (1, 256))
        self.assertTrue(service._cache_to_disk_config(500) == (2, 256))
        self.assertTrue(service._cache_to_disk_config(512) == (2, 256))
        self.assertTrue(service._cache_to_disk_config(750) == (3, 256))
        self.assertTrue(service._cache_to_disk_config(1000) == (4, 256))
        self.assertTrue(service._cache_to_disk_config(1500) == (3, 512))
        self.assertTrue(service._cache_to_disk_config(4000) == (8, 512))
        self.assertTrue(service._cache_to_disk_config(5000) == (5, 1024))
        self.assertTrue(service._cache_to_disk_config(8000) == (8, 1024))
        self.assertTrue(service._cache_to_disk_config(30000) == (8, 4095))

    def test__get_network(self):
        service = self.mk_azure_service()
        self.assertTrue(service._get_network())

    def test__list_storage_accounts(self):
        service = self.mk_azure_service()
        self.assertTrue(service._list_storage_accounts())

    def test_bad_container_name(self):
        service = self.mk_azure_service()
        self.assertTrue(service.valid_containername('some-container'))
        self.assertFalse(service.valid_containername(''))
        self.assertFalse(service.valid_containername('---------------'))
        self.assertFalse(service.valid_containername('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'))
        self.assertRaises(vFXT.service.vFXTConfigurationException, service.create_container, '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890')

    def test_create_delete_container(self):
        from vFXT.msazure import ContainerExistsException
        service = self.mk_azure_service()
        name = '{}/{}'.format(service.storage_account, str(uuid.uuid4()).lower().replace('-', '')[0:55])
        self.assertTrue(service.create_container(name))
        self.assertRaises(ContainerExistsException, service.create_container, name)
        service.delete_container(name)


if __name__ == '__main__':
    unittest.main()
