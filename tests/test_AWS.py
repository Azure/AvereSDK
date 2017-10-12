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
import time
import uuid
import logging

import boto.ec2
import boto.s3
import boto.vpc
import boto.iam

import vFXT.service

from vFXT.aws import Service
import tests.vFXTTestCase

logging.basicConfig()
log = logging.getLogger(__name__)

class AWS_test(tests.vFXTTestCase.Base):
    def setUp(self):
        tests.vFXTTestCase.Base.setUp(self)
        if not self.aws['enabled']:
            self.skipTest("skipping tests for AWS")

    def test__init__(self):
        service = self.mk_aws_service()
        self.assertIsInstance(service, vFXT.aws.Service)

    def test_from_environment_init(self):
        if not self.aws['check_from_environment']:
            self.skipTest("skipping check_from_environment test")
        service = Service.environment_init(region=self.aws['region'], subnet=self.aws['subnet'])
        self.assertIsInstance(service, vFXT.aws.Service)

    def test_on_instance_init(self):
        if not self.aws['check_on_instance']:
            self.skipTest("skipping check_on_instance test")
        service = Service.on_instance_init()
        self.assertIsInstance(service, vFXT.aws.Service)

    def test_connection(self):
        service = self.mk_aws_service()
        self.assertIsInstance(service.connection('ec2'), boto.ec2.connection.EC2Connection)
        self.assertIsInstance(service.connection('vpc'), boto.vpc.VPCConnection)
        self.assertIsInstance(service.connection('s3'), boto.s3.connection.S3Connection)
        self.assertIsInstance(service.connection('iam'), boto.iam.connection.IAMConnection)

    def test_bad_region(self):
        self.assertRaises(vFXT.service.vFXTServiceConnectionFailure,
            Service,
                region='this is an invalid region',
                access_key=self.aws['access_key'],
                secret_access_key=self.aws['secret_access_key'],
                s3_access_key=self.aws['s3_access_key'],
                s3_secret_access_key=self.aws['s3_secret_access_key'],
                subnet=self.aws['subnet']
        )

    def test_bad_proxy(self):
        self.assertRaises(vFXT.service.vFXTServiceConnectionFailure, Service,
            region='invalid',
            access_key=self.aws['access_key'],
            secret_access_key=self.aws['secret_access_key'],
            subnet=self.aws['subnet'],
            proxy_uri='http://172.16.30.30:9999')

    def test_no_subnets(self):
        self.assertRaises(vFXT.service.vFXTConfigurationException,
            Service,
                region=self.aws['region'],
                access_key=self.aws['access_key'],
                secret_access_key=self.aws['secret_access_key'],
                s3_access_key=self.aws['s3_access_key'],
                s3_secret_access_key=self.aws['s3_secret_access_key'],
                subnet=None
        )

    def test_find_instance(self):
        service = self.mk_aws_service()
        instances = service.find_instances()
        self.assertTrue(len(instances) > 0, msg="Assuming we always have instances")

    def test_get_instances(self):
        service = self.mk_aws_service()
        instances = service.get_instances(self.aws['existing'])
        self.assertTrue(len(instances) == len(self.aws['existing']), msg="Checking for our basic service instances")

    def test_get_instance(self):
        service = self.mk_aws_service()
        instance = service.get_instance(self.aws['existing'][0])
        self.assertIsInstance(instance, boto.ec2.instance.Instance)

    def test_create_instance(self):
        from vFXT.serviceInstance import ServiceInstance
        service = self.mk_aws_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))
        instance = ServiceInstance.create(service, self.aws['instance_type'], name, self.aws['ami'], subnet=self.aws['subnet'], tags={'Name': name})
        self.assertTrue(instance.instance.tags['Name'] == name)

        try:
            self.assertTrue(instance.name())
            self.assertTrue(instance.id())
            self.assertTrue(instance.ip())
            self.assertTrue(instance.fqdn())
            self.assertTrue(instance.status())

            instance.add_address('172.16.200.200')
            instance.refresh()
            self.assertTrue('172.16.200.200' in instance.in_use_addresses())
            # duplicate failure
            self.assertRaises(vFXT.service.vFXTConfigurationException, instance.add_address, '172.16.200.200')
            instance.remove_address('172.16.200.200')
            instance.refresh()
            self.assertFalse('172.16.200.200' in instance.in_use_addresses())

            self.assertTrue(instance.is_on())
            if service.can_stop(instance.instance):
                instance.stop()
                self.assertTrue(instance.is_off())
            if instance.is_off():
                instance.start()
                self.assertTrue(instance.is_on())
            instance.restart()
            self.assertTrue(instance.is_on())
        except Exception as e:
            log.error(e)
            raise
        finally:
            instance.destroy()

    def test_bad_bucket_name(self):
        service = self.mk_aws_service()
        self.assertTrue(service.valid_bucketname('some-bucket'))
        self.assertFalse(service.valid_bucketname(''))
        self.assertFalse(service.valid_bucketname('---------------'))
        self.assertFalse(service.valid_bucketname('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'))
        self.assertRaises(vFXT.service.vFXTConfigurationException, service.create_bucket, '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890')

    def test_valid_instancename(self):
        service = self.mk_aws_service()
        self.assertTrue(service.valid_instancename('name'))
        self.assertTrue(service.valid_instancename('1name'))
        self.assertTrue(service.valid_instancename('name1'))
        self.assertTrue(service.valid_instancename('name with spaces'))
        self.assertTrue(service.valid_instancename('name\twith\ttabs'))
        self.assertTrue(service.valid_instancename('@foobar'))
        self.assertTrue(service.valid_instancename('firstname.lastname'))
        self.assertTrue(service.valid_instancename('firstname-lastname'))
        self.assertTrue(service.valid_instancename('firstname+lastname'))
        self.assertTrue(service.valid_instancename('firstname=lastname'))
        self.assertTrue(service.valid_instancename('firstname_lastname'))
        self.assertTrue(service.valid_instancename('firstname:lastname'))
        self.assertTrue(service.valid_instancename('firstname/lastname'))
        self.assertFalse(service.valid_instancename('firstname&lastname'))
        self.assertFalse(service.valid_instancename('firstname^lastname'))
        self.assertFalse(service.valid_instancename('firstname$lastname'))
        self.assertFalse(service.valid_instancename('[name]'))
        self.assertFalse(service.valid_instancename('(name)'))
        self.assertTrue(service.valid_instancename(' starts with a space'))
        self.assertTrue(service.valid_instancename('\tstarts with a tab'))
        self.assertTrue(service.valid_instancename('10xvfxttest'))
        self.assertFalse(service.valid_instancename('aws:badprefix'))
        self.assertTrue(service.valid_instancename('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'))
        self.assertFalse(service.valid_instancename('123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'))

    def test_default_router(self):
        service = self.mk_aws_service()
        self.assertTrue(service.get_default_router(subnet_id=self.aws['subnet']))
        self.assertTrue(service.get_default_router())
    def test_default_dns(self):
        service = self.mk_aws_service()
        self.assertTrue(service.get_dns_servers(subnet_id=self.aws['subnet']))
        result = service.get_dns_servers()
        self.assertTrue(result)
        self.assertTrue(service.get_dns_servers() == result)
    def test_default_ntp(self):
        service = self.mk_aws_service()
        result = service.get_ntp_servers()
        self.assertTrue(result)
        self.assertTrue(service.get_ntp_servers() == result)
    def test_all_default_ntp(self):
        # we should always get a response for any subnet, either subnet
        # configuration or our built in defaults
        service = self.mk_aws_service()
        for sn in service._get_all_subnets():
            result = service.get_ntp_servers(sn.id)
            self.assertTrue(result)

    def test_instance_in_use_addresses(self):
        service = self.mk_aws_service()
        instance = service.get_instance(self.aws['existing'][0]) # well known instance
        self.assertTrue(service.instance_in_use_addresses(instance))

    def test_get_route_tables(self):
        service = self.mk_aws_service()
        route_tables = service._get_route_tables()
        self.assertTrue(route_tables)

    def test_export(self):
        service = self.mk_aws_service()
        d = service.export()
        s = Service(**d)
        d2 = s.export()
        self.assertDictEqual(d, d2)

    def test_refresh(self):
        service = self.mk_aws_service()
        instance = service.get_instance(self.aws['existing'][0])
        self.assertIsInstance(instance, boto.ec2.instance.Instance)
        refreshed = service.refresh(instance)
        self.assertIsInstance(refreshed, boto.ec2.instance.Instance)

    def test_get_available_addresses(self):
        service = self.mk_aws_service()
        addresses = service.get_available_addresses()
        self.assertTrue(addresses)
        self.assertTrue(service.get_available_addresses(count=2))
        self.assertTrue(service.get_available_addresses(count=2, contiguous=False))

    def test_create_delete_bucket(self):
        service = self.mk_aws_service()
        name = '{}'.format(str(uuid.uuid4()).lower().replace('-', '')[0:55])
        service.create_bucket(name)
        service.delete_bucket(name)

    def test_get_subnet(self):
        service = self.mk_aws_service()
        self.assertTrue(service._get_subnet())

    def test_subnet_to_vpc(self):
        service = self.mk_aws_service()
        self.assertTrue(service._subnet_to_vpc())

    def test_iam(self):
        service = self.mk_aws_service()
        name = str(uuid.uuid4())
        self.assertTrue(service._create_iamrole(name))
        self.assertTrue(service._get_iamrole(name))
        service._delete_iamrole(name)

    def test_region_names(self):
        service = self.mk_aws_service()
        self.assertTrue(service._region_names())

    def test_move_route(self):
        from vFXT.serviceInstance import ServiceInstance
        service = self.mk_aws_service()
        i1 = None
        i2 = None
        try:
            i1 = ServiceInstance.create(service, self.aws['instance_type'], 'vfxttest-dup-route-1', self.aws['ami'])
            i2 = ServiceInstance.create(service, self.aws['instance_type'], 'vfxttest-dup-route-2', self.aws['ami'])

            i1.add_address('172.16.200.201')
            i2.add_address('172.16.200.201')
            i1.refresh()
            i2.refresh()
            self.assertTrue('172.16.200.201' not in i1.in_use_addresses())
            self.assertTrue('172.16.200.201' in i2.in_use_addresses())

        finally:
            if i1:
                i1.destroy()
            if i2:
                i2.destroy()

    def test_cache_to_disk_config(self):
        service = self.mk_aws_service()
        self.assertTrue(service._cache_to_disk_config(250) == (1, 250))
        self.assertTrue(service._cache_to_disk_config(500) == (1, 500))
        self.assertTrue(service._cache_to_disk_config(1000) == (10, 100))
        self.assertTrue(service._cache_to_disk_config(1500) == (10, 150))
        self.assertTrue(service._cache_to_disk_config(4000) == (10, 400))
        self.assertTrue(service._cache_to_disk_config(8000) == (10, 800))

    def test__get_all_subnets(self):
        service = self.mk_aws_service()
        self.assertTrue(service._get_all_subnets())

    def test_check(self):
        service = self.mk_aws_service()
        self.assertTrue(service.check() is None)


if __name__ == '__main__':
    unittest.main()
