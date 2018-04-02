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
import uuid
import time
import os
import tempfile
import logging

import googleapiclient

import vFXT
from vFXT.gce import Service
import vFXT.service
import tests.vFXTTestCase

logging.basicConfig()

class GCE_test(tests.vFXTTestCase.Base):
    def setUp(self):
        tests.vFXTTestCase.Base.setUp(self)
        if not self.gce['enabled']:
            self.skipTest("skipping tests for GCE")

    def test__init__(self):
        service = self.mk_gce_service()
        self.assertIsInstance(service, vFXT.gce.Service)

    def test_from_environment_init(self):
        if not self.gce['check_from_environment']:
            self.skipTest("skipping check_from_environment test")
        service = Service.environment_init(zone=self.gce['zone_id'], project_id=self.gce['project_id'], network_id=self.gce['network_id'])
        self.assertIsInstance(service, vFXT.gce.Service)

    def test_on_instance_init(self):
        if not self.gce['check_on_instance']:
            self.skipTest("skipping check_on_instance test")
        service = Service.on_instance_init()
        self.assertIsInstance(service, vFXT.gce.Service)

    def test__init___with_key(self):
        service = self.mk_gce_service()
        withkey = Service(client_email=service.client_email, key_file=self.gce['key_file'], zone=service.zones[0], project_id=service.project_id, network_id=service.network_id)
        self.assertIsInstance(withkey, vFXT.gce.Service)

    def test__init___with_bad_keyfile(self):
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, client_email='', zone='', project_id='', network_id='')
        # non json file makes it through file presence check
        self.assertRaises(vFXT.service.vFXTServiceConnectionFailure, Service, client_email='fake', key_file='not_real', zone='', project_id='fake', network_id='')
        # No such file or directory
        self.assertRaises(IOError, Service, client_email='fake', key_file='not_real.json', zone='', project_id='fake', network_id='')
        fd, name = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(fd, 'w') as f:
                import json
                key_data = json.load(open(self.gce['key_file']))
                del key_data['client_email']
                json.dump(key_data, f)
            self.assertRaises(vFXT.service.vFXTConfigurationException, Service, key_file=name, zone='', project_id='fake', network_id='')
        finally:
            os.remove(name)

    def test__init___with_key_data(self):
        service = self.mk_gce_service()
        import json
        key_data = json.load(open(self.gce['key_file']))
        withkey = Service(key_data=key_data, zone=service.zones[0], network_id=service.network_id)
        self.assertIsInstance(withkey, vFXT.gce.Service)

    def test__init___with_bad_key_data(self):
        service = self.mk_gce_service()
        import json
        key_data = json.load(open(self.gce['key_file']))
        del key_data['client_email']
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, key_data=key_data, zone=service.zones[0], network_id=service.network_id)
        key_data = json.load(open(self.gce['key_file']))
        del key_data['project_id']
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, key_data=key_data, zone=service.zones[0], network_id=service.network_id)

    def test_init__with_incomplete(self):
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, network_id='', zone='', project_id='', client_email='')
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, network_id='', zone='', project_id='asdf', client_email='')

    def test__init__with_bad_proxy(self):
        service = self.mk_gce_service()
        self.assertRaises(vFXT.service.vFXTServiceConnectionFailure, Service, key_file=service.key_file, zone=service.zones[0], project_id=service.project_id, network_id=service.network_id, proxy_uri='http://172.16.30.30:9999')

    def test__init__with_bad_subnetwork(self):
        service = self.mk_gce_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, key_file=service.key_file, zone=service.zones[0], project_id=service.project_id, network_id=service.network_id, subnetwork_id='nosuchsubnetwork')

    def test_connection(self):
        service = self.mk_gce_service()
        self.assertIsInstance(service.connection('compute'), googleapiclient.discovery.Resource)
        self.assertIsInstance(service.connection('storage'), googleapiclient.discovery.Resource)

    def test_connection_garbage_auth(self):
        # garbage auth
        self.assertRaises(vFXT.service.vFXTConfigurationException, Service, client_email='garbage', key_file='tests/fake_key.p12', zone='', project_id='', network_id='')

    def test_connection_bad_project(self):
        self.skipTest("This test does not work with json key file... it always provides the correct project id")
        service = self.mk_gce_service()
        r = 'a{}a'.format(str(uuid.uuid4()).lower().replace('-', '')[0:55])
        self.assertRaises(vFXT.service.vFXTServiceConnectionFailure, Service, client_email=service.client_email, key_file=service.key_file, zone=service.zones[0], project_id=r, network_id=service.network_id)

    # this doesn't raise with the new simplified connection test
    #def test_connection_bad_zone(self):
    #    service = self.mk_gce_service()
    #    r = 'a{}a'.format(str(uuid.uuid4()).lower().replace('-','')[0:55])
    #    self.assertRaises(vFXT.service.vFXTConfigurationException, Service,client_email=service.client_email, key=service.key.encode('base64'), zone=r, project_id=service.project_id, network_id=service.network_id)

    def test_connection_expired(self):
        service = self.mk_gce_service()
        service.connection_test()
        delattr(service.local, 'connections')
        service.connection_test()

    def test_findInstance(self):
        service = self.mk_gce_service()
        instances = service.find_instances()
        self.assertTrue(len(instances) > 0, msg="Assuming we always have instances")

    def test_get_instances(self):
        service = self.mk_gce_service()
        instances = service.get_instances(self.gce['existing'])
        self.assertTrue(len(instances) == len(self.gce['existing']), msg="Checking for our basic service instances")

    def test_get_instance(self):
        service = self.mk_gce_service()
        instance = service.get_instance(self.gce['existing'][0])
        self.assertIsInstance(instance, dict, msg="GCE returns a dict of instance information")

    def test_get_network(self):
        service = self.mk_gce_service()
        network = service._get_network()
        self.assertTrue(network['name'] == service.network_id)

    def test_valid_bucketname(self):
        service = self.mk_gce_service()
        self.assertTrue(service.valid_bucketname("this-is-a-bucket"))
        self.assertFalse(service.valid_bucketname("this-not-is-a-bucket."))
        self.assertFalse(service.valid_bucketname("goog-cannot-come-first"))
        self.assertFalse(service.valid_bucketname("cannot-have-google-in-the-name"))
        self.assertFalse(service.valid_bucketname("cannot-have-gogle-in-the-name"))
        self.assertFalse(service.valid_bucketname("cannot-have-g00gle-in-the-name"))
        self.assertFalse(service.valid_bucketname("cannot-have-googgle-in-the-name"))
        self.assertFalse(service.valid_bucketname("cannot-have-goog1e-in-the-name"))
        self.assertFalse(service.valid_bucketname("4"))
        self.assertFalse(service.valid_bucketname("this-is-an-insanely-long-bucket-name-that-actually-is-not-valid-this-is-an-insanely-long-bucket-name-that-actually-is-not-valid"))
        self.assertFalse(service.valid_bucketname('this-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-namethis-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-namethis-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-namethis-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-name'))

    def test_valid_instancename(self):
        service = self.mk_gce_service()
        self.assertTrue(service.valid_instancename("vfxttest-lg-1"))
        self.assertFalse(service.valid_instancename("Z"))
        self.assertFalse(service.valid_instancename("6"))
        self.assertFalse(service.valid_instancename("this-is-an-insanely-long-instance-name-that-actually-is-not-a-valid-name"))

    def test_create_instance(self):
        from vFXT.serviceInstance import ServiceInstance
        service = self.mk_gce_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))
        instance = ServiceInstance.create(service, self.gce['instance_type'], name, self.gce['image'], metadata={'purpose': 'test'}, tags=['avere-dev'])
        self.assertTrue('avere-dev' in instance.instance['tags']['items'])
        self.assertTrue(service._get_metadata(instance.instance, 'purpose') == 'test')

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

            # metadata
            instance.refresh()
            metadata_value = str(uuid.uuid4())
            service._set_metadata(instance.instance, 'metadata_test', metadata_value)
            instance.refresh()
            self.assertTrue(metadata_value == service._get_metadata(instance.instance, 'metadata_test'))
            service._delete_metadata(instance.instance, 'metadata_test')
            instance.refresh()
            self.assertFalse(service._get_metadata(instance.instance, 'metadata_test'))

            # tags
            instance.refresh()
            service._add_tag(instance.instance, 'vfxttest-tag-test')
            instance.refresh()
            self.assertTrue('vfxttest-tag-test' in instance.instance['tags']['items'])
            service._remove_tag(instance.instance, 'vfxttest-tag-test')
            instance.refresh()
            self.assertFalse('vfxttest-tag-test' in instance.instance['tags']['items'])

            self.assertTrue(instance.is_on())
            if service.can_stop(instance.instance):
                instance.stop()
                self.assertTrue(instance.is_off())
            if instance.is_off():
                instance.start()
                self.assertTrue(instance.is_on())
            instance.restart()
            self.assertTrue(instance.is_on())
        finally:
            instance.destroy()

    def test_bad_bucket_name(self):
        service = self.mk_gce_service()
        self.assertTrue(service.valid_bucketname('some-bucket'))
        self.assertFalse(service.valid_bucketname(''))
        self.assertFalse(service.valid_bucketname('---------------'))
        self.assertFalse(service.valid_bucketname('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890'))
        self.assertRaises(vFXT.service.vFXTConfigurationException, service.create_bucket, '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890')

    def test_default_router(self):
        service = self.mk_gce_service()
        self.assertTrue(service.get_default_router())
    def test_default_dns(self):
        service = self.mk_gce_service()
        result = service.get_dns_servers()
        self.assertTrue(result)
        self.assertTrue(service.get_dns_servers() == result)
    def test_default_ntp(self):
        service = self.mk_gce_service()
        result = service.get_ntp_servers()
        self.assertTrue(result)
        self.assertTrue(service.get_ntp_servers() == result)

    def test_export(self):
        service = self.mk_gce_service()
        d = service.export()
        s = Service(**d)
        d2 = s.export()
        self.assertDictEqual(d, d2)

    def test_refresh(self):
        service = self.mk_gce_service()
        instance = service.get_instance(self.gce['existing'][0])
        self.assertIsInstance(instance, dict, msg="GCE returns a dict of instance information")
        refreshed = service.refresh(instance)
        self.assertIsInstance(refreshed, dict, msg="GCE returns a dict of instance information")

    def test_instance_in_use_addresses(self):
        service = self.mk_gce_service()
        instance = service.get_instance(self.gce['existing'][0]) # well known instance
        self.assertTrue(service.instance_in_use_addresses(instance))

    def test_get_available_addresses(self):
        service = self.mk_gce_service()
        self.assertTrue(service.get_available_addresses())

    def test_create_delete_bucket(self):
        service = self.mk_gce_service()
        name = '{}'.format(str(uuid.uuid4()).lower().replace('-', '')[0:55])
        service.create_bucket(name)
        service.delete_bucket(name)

    def test_create_bucket_storage_classes(self):
        service = self.mk_gce_service()
        name = '{}'.format(str(uuid.uuid4()).lower().replace('-', '')[0:55])
        for storage_class in service.STORAGE_CLASSES:
            b = service.create_bucket(name, storage_class=storage_class)
            try:
                self.assertTrue(b['storageClass'] == storage_class)
            finally:
                service.delete_bucket(name)
            # need to throttle. "The project exceeded the rate limit for creating and deleting buckets"
            time.sleep(60)

    def test_gs_get_object(self):
        service = self.mk_gce_service()
        fd, name = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as f:
            service._gs_get_object(self.gce['bucket'], self.gce['bucket_file'], f)
            f.close()
            os.remove(name)

    def test_gs_fetch(self):
        service = self.mk_gce_service()
        fd, name = tempfile.mkstemp()
        os.close(fd)
        os.unlink(name)
        obj_url = 'gs://{}/{}'.format(self.gce['bucket'], self.gce['bucket_file'])
        try:
            service._gs_fetch(obj_url, name)
        finally:
            try:
                os.unlink(name)
            except Exception: pass

    def test_move_route(self):
        from vFXT.serviceInstance import ServiceInstance
        service = self.mk_gce_service()
        i1 = None
        i2 = None
        try:
            i1 = ServiceInstance.create(service, self.gce['instance_type'], 'vfxttest-dup-route-1', self.gce['image'], metadata={'purpose': 'test'}, tags=['avere-dev'])
            i2 = ServiceInstance.create(service, self.gce['instance_type'], 'vfxttest-dup-route-2', self.gce['image'], metadata={'purpose': 'test'}, tags=['avere-dev'])

            addrs, mask = service.get_available_addresses(count=2, addr_range='172.16.16.0/24') #pylint: disable=unused-variable
            addr = addrs[0]

            i1.add_address(addr)
            i2.add_address(addr)
            i1.refresh()
            i2.refresh()
            self.assertTrue(addr not in i1.in_use_addresses())
            self.assertTrue(addr in i2.in_use_addresses())

            # add a different kind of route
            addr = addrs[1]
            route_body = {
                'name': 'reservation-{}'.format(addr.replace('.', '-')),
                'network': service._get_network()['selfLink'],
                'nextHopIp': service.get_default_router(),
                'priority': 900,
                'destRange': '{}/32'.format(addr)
            }
            op = vFXT.gce._gce_do(service.connection().routes().insert, project=service.network_project_id, body=route_body) #pylint: disable=unused-variable
            # Just do it... we will fix it up later# service._wait_for_operation(op, msg='route to be reserved', op_type='globalOperations')
            # we should be able to take it
            i2.add_address(addr)
            i2.refresh()
            self.assertTrue(addr in i2.in_use_addresses())

        finally:
            if i1:
                i1.destroy()
            if i2:
                i2.destroy()

    def test_cache_to_disk_config(self):
        service = self.mk_gce_service()
        self.assertTrue(service._cache_to_disk_config(250) == (1, 250))
        self.assertTrue(service._cache_to_disk_config(500) == (1, 500))
        self.assertTrue(service._cache_to_disk_config(1000) == (1, 1000))
        self.assertTrue(service._cache_to_disk_config(1500) == (1, 1500))
        self.assertTrue(service._cache_to_disk_config(4000) == (1, 4000))
        self.assertTrue(service._cache_to_disk_config(8000) == (1, 8000))
        self.assertTrue(service._cache_to_disk_config(250, disk_type='local-ssd') == (1, 375))
        self.assertTrue(service._cache_to_disk_config(500, disk_type='local-ssd') == (2, 375))
        self.assertTrue(service._cache_to_disk_config(1000, disk_type='local-ssd') == (3, 375))
        self.assertTrue(service._cache_to_disk_config(1500, disk_type='local-ssd') == (4, 375))
        self.assertTrue(service._cache_to_disk_config(2000, disk_type='local-ssd') == (6, 375))
        self.assertTrue(service._cache_to_disk_config(2500, disk_type='local-ssd') == (7, 375))
        self.assertTrue(service._cache_to_disk_config(3000, disk_type='local-ssd') == (8, 375))
        self.assertRaises(vFXT.service.vFXTConfigurationException, service._cache_to_disk_config, 3001, disk_type='local-ssd')

    def test_zone_names(self):
        service = self.mk_gce_service()

        zones = service._zone_names()
        self.assertTrue(zones)
        self.assertTrue(service._zone_to_region(zones[0]))
        self.assertTrue(service._zone_machine_types())
        self.assertRaises(vFXT.service.vFXTConfigurationException, service._zone_to_region, 'invalid-zone')

    def test_check(self):
        service = self.mk_gce_service()
        self.assertTrue(service.check() is None)


if __name__ == '__main__':
    unittest.main()
