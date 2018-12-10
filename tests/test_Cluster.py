#!/usr/bin/python
# Copyright (c) 2015-2018 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
import unittest
import time
import logging

from vFXT.cluster import Cluster
import vFXT.service
import tests.vFXTTestCase

logging.basicConfig()
log = logging.getLogger(__name__)

class Cluster_test(tests.vFXTTestCase.Base):
    customize_corefiler_name = lambda x: x

    def test__init__aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        aws = self.mk_aws_service()
        self.assertIsInstance(aws, vFXT.aws.Service)
        cluster = Cluster(service=aws)
        self.assertIsInstance(cluster, Cluster)

    def _run_cluster_steps(self, cluster, skip_corefiler=False, use_instance_for_mgmt=False):
        service = cluster.service

        self.assertIsInstance(cluster, Cluster)
        self.assertTrue(cluster.is_on())
        self.assertTrue(len(cluster.nodes) == 3)

        self.assertTrue(cluster.xmlrpc().cluster.get())

        # verify we can load the cluster and get the same info back
        mgmt_ip = cluster.nodes[0].ip() if use_instance_for_mgmt else cluster.mgmt_ip
        loaded = Cluster.load(service, mgmt_ip=mgmt_ip, admin_password=cluster.admin_password)
        self.assertTrue(len(loaded.nodes) == len(cluster.nodes))
        loaded_export  = loaded.export()
        cluster_export = cluster.export()
        loaded_export['nodes'].sort() # may be out of order
        cluster_export['nodes'].sort() # may be out of order
        self.assertDictEqual(cluster_export, loaded_export)

        initted = Cluster(service, **loaded_export)
        initted_export = initted.export()
        initted_export['nodes'].sort() # may be out of order
        self.assertDictEqual(cluster_export, initted_export)

        # add vserver, corefiler
        cluster.add_vserver('vserver')
        cluster.wait_for_healthcheck(state='green', duration=10)
        self.assertTrue(cluster.xmlrpc().vserver.get('vserver'))
        if not skip_corefiler:
            corefiler_name = self.customize_corefiler_name(cluster.name)
            cluster.make_test_bucket(corefiler_name)
            self.assertTrue(corefiler_name in cluster.xmlrpc().corefiler.list())
            cluster.add_vserver_junction('vserver', corefiler_name)

        self.assertTrue(cluster.in_use_addresses())
        self.assertTrue(cluster.in_use_addresses('mgmt'))
        self.assertTrue(cluster.in_use_addresses('vserver'))
        self.assertTrue(cluster.in_use_addresses('cluster'))

        node_count = len(cluster.nodes)
        cluster.add_nodes(2)
        cluster.rebalance_directory_managers()
        new_node_count = len(cluster.nodes)
        self.assertTrue(new_node_count > node_count)
        self.assertTrue(new_node_count == len(cluster.xmlrpc().node.list()))

        if self.shelve:
            cluster.shelve()
            self.assertTrue(cluster.is_off())
            self.assertTrue(cluster.is_shelved())

            cluster.unshelve()
            cluster.wait_for_healthcheck(state='red', duration=1)
            self.assertTrue(cluster.is_on())
            self.assertFalse(cluster.is_shelved())

    def test_create_aws(self):
        if not self.create_clusters:
            self.skipTest("skipping full cluster create tests for AWS")
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")

        service = self.mk_aws_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))
        cluster = Cluster.create(service, self.aws['instance_type'], name, 'adminpass', root_image=self.aws['vfxt_image'], wait_for_state='yellow', tags={'vfxtpy-unittest': 'auto'})

        try:
            self._run_cluster_steps(cluster)
        except Exception as e:
            log.error(e)
            raise
        finally:
            cluster.destroy(quick_destroy=True)
            cleanups = [service.instance_id(_) for _ in service.find_instances() if name in service.name(_)]
            if cleanups:
                Cluster(service, nodes=cleanups).destroy(quick_destroy=True)

    def test__init__gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")

        gce = self.mk_gce_service()
        self.assertIsInstance(gce, vFXT.gce.Service)
        cluster = Cluster(service=gce)
        self.assertIsInstance(cluster, Cluster)

    def test_create_gce(self):
        if not self.create_clusters:
            self.skipTest("skipping full cluster create tests for GCE")
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")

        service = self.mk_gce_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))
        cluster = Cluster.create(service, self.gce['instance_type'], name, 'adminpass', root_image=self.gce['vfxt_image'], size=3, wait_for_state='yellow', tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})

        try:
            self._run_cluster_steps(cluster)
        except Exception as e:
            log.error(e)
            raise
        finally:
            cluster.destroy(quick_destroy=True)
            cleanups = [service.instance_id(_) for _ in service.find_instances() if name in service.name(_)]
            if cleanups:
                Cluster(service, nodes=cleanups).destroy(quick_destroy=True)

    def test__init__azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")

        azure = self.mk_azure_service()
        self.assertIsInstance(azure, vFXT.msazure.Service)
        cluster = Cluster(service=azure)
        self.assertIsInstance(cluster, Cluster)

    def test_create_azure(self):
        if not self.create_clusters:
            self.skipTest("skipping full cluster create tests for Azure")
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")

        service = self.mk_azure_service()
        name = 'vfxt-unittest-{}'.format(int(time.time()))
        cluster = Cluster.create(service, self.azure['instance_type'], name, 'adminpass', root_image=self.azure['vfxt_image'], size=3, wait_for_state='yellow', azure_role=self.azure['role'])

        self.assertIsInstance(cluster, Cluster)
        self.assertTrue(cluster.is_on())
        self.assertTrue(len(cluster.nodes) == 3)

        self.assertTrue(cluster.xmlrpc().cluster.get())

        def _azure_storage_account_fixup(name):
            return '{}/{}'.format(self.azure['storage_account'], name)
        self.customize_corefiler_name = _azure_storage_account_fixup

        try:
            self._run_cluster_steps(cluster, use_instance_for_mgmt=True)
        except Exception as e:
            log.error(e)
            raise
        finally:
            cluster.destroy(quick_destroy=True)
            cleanups = [service.instance_id(_) for _ in service.find_instances() if name in service.name(_)]
            if cleanups:
                Cluster(service, nodes=cleanups).destroy(quick_destroy=True)

    def test_bad_machine_type_aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        aws = self.mk_aws_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, aws, 'bogus', 'clustername', 'adminpass')

    def test_bad_machine_type_gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")
        gce = self.mk_gce_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, gce, 'bogus', 'clustername', 'adminpass')

    def test_bad_machine_type_azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")
        azure = self.mk_azure_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, azure, 'bogus', 'clustername', 'adminpass')

    def test_bad_cluster_name_aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        aws = self.mk_aws_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, aws, self.aws['instance_type'], '', 'adminpass')
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, aws, self.aws['instance_type'], '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890', 'adminpass')

    def test_bad_cluster_name_azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")
        azure = self.mk_azure_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, azure, self.azure['instance_type'], '', 'adminpass')
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, azure, self.azure['instance_type'], '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890', 'adminpass')

    def test_bad_cluster_name_gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")
        gce = self.mk_gce_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, gce, self.gce['instance_type'], '', 'adminpass')
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, gce, self.gce['instance_type'], '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890', 'adminpass')

    def test_in_use_mgmt_ip_fail_aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        service = self.mk_aws_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.aws['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.aws['instance_type'], name, 'adminpass', management_address=existing_address, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_aws_in_use_mgmt_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_instance_ip_fail_aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        service = self.mk_aws_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.aws['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.aws['instance_type'], name, 'adminpass', instance_addresses=[existing_address], size=1, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_aws_in_use_instance_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_cluster_ip_fail_aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        service = self.mk_aws_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.aws['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.aws['instance_type'], name, 'adminpass', address_range_start=existing_address, address_range_end=vFXT.Cidr.to_address(vFXT.Cidr.from_address(existing_address) + 1), address_range_netmask='255.255.255.255', size=1, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_aws_in_use_cluster_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_mgmt_ip_fail_azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")
        service = self.mk_azure_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.azure['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.azure['instance_type'], name, 'adminpass', management_address=existing_address, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_azure_in_use_mgmt_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_instance_ip_fail_azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")
        service = self.mk_azure_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.azure['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.azure['instance_type'], name, 'adminpass', instance_addresses=[existing_address], size=1, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_azure_in_use_instance_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_cluster_ip_fail_azure(self):
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")
        service = self.mk_azure_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.azure['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.azure['instance_type'], name, 'adminpass', address_range_start=existing_address, address_range_end=vFXT.Cidr.to_address(vFXT.Cidr.from_address(existing_address) + 1), address_range_netmask='255.255.255.255', size=1, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_azure_in_use_cluster_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_mgmt_ip_fail_gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")
        service = self.mk_gce_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.gce['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.gce['instance_type'], name, 'adminpass', management_address=existing_address, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_gce_in_use_mgmt_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_instance_ip_fail_gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")
        service = self.mk_gce_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.gce['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.gce['instance_type'], name, 'adminpass', instance_addresses=[existing_address], size=1, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_gce_in_use_instance_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_in_use_cluster_ip_fail_gce(self):
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")
        service = self.mk_gce_service()
        name = 'vfxtpy-unittest-{}'.format(int(time.time()))

        instances = service.get_instances(self.gce['existing'])
        existing_address = service.ip(instances[0])
        def _should_fail():
            cluster = Cluster.create(service, self.gce['instance_type'], name, 'adminpass', address_range_start=existing_address, address_range_end=vFXT.Cidr.to_address(vFXT.Cidr.from_address(existing_address) + 1), address_range_netmask='255.255.255.255', size=1, tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
            # the above should not complete... but if it does
            cluster.destroy(quick_destroy=True)
            raise Exception("test_gce_in_use_cluster_ip_fail did not fail")
        self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail)

    def test_bad_add_node_ip_validation_azure(self):
        if not self.create_clusters:
            self.skipTest("skipping full cluster create tests for Azure")
        if not self.azure['enabled']:
            self.skipTest("skipping test for Azure")
        service = self.mk_azure_service()

        instances = service.get_instances(self.azure['existing'])
        existing_address = service.ip(instances[0])

        name = 'vfxt-unittest-{}'.format(int(time.time()))
        cluster = Cluster.create(service, self.azure['instance_type'], name, 'adminpass', root_image=self.azure['vfxt_image'], size=3, wait_for_state='yellow', azure_role=self.azure['role'])
        try:
            def _should_fail_instance_in_use():
                cluster.add_nodes(1, instance_addresses=[existing_address])
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_instance_in_use)
            def _should_fail_not_enough_instance():
                cluster.add_nodes(2, instance_addresses=[existing_address])
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_not_enough_instance)
            def _should_fail_not_enough_cluster():
                cluster.add_nodes(2, address_range_start=existing_address, address_range_end=existing_address, address_range_netmask='255.255.255.255')
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_not_enough_cluster)
            def _should_fail_cluster_in_use():
                cluster.add_nodes(1, address_range_start=existing_address, address_range_end=existing_address, address_range_netmask='255.255.255.255')
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_cluster_in_use)
        finally:
            cluster.destroy(quick_destroy=True)

    def test_bad_add_node_ip_validation_aws(self):
        if not self.create_clusters:
            self.skipTest("skipping full cluster create tests for AWS")
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        service = self.mk_aws_service()

        instances = service.get_instances(self.aws['existing'])
        existing_address = service.ip(instances[0])

        name = 'vfxtpy-unittest-{}'.format(int(time.time()))
        cluster = Cluster.create(service, self.aws['instance_type'], name, 'adminpass', root_image=self.aws['vfxt_image'], wait_for_state='yellow', tags={'vfxtpy-unittest': 'auto'})
        try:
            def _should_fail_instance_in_use():
                cluster.add_nodes(1, instance_addresses=[existing_address])
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_instance_in_use)
            def _should_fail_not_enough_instance():
                cluster.add_nodes(2, instance_addresses=[existing_address])
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_not_enough_instance)
            def _should_fail_not_enough_cluster():
                cluster.add_nodes(2, address_range_start=existing_address, address_range_end=existing_address, address_range_netmask='255.255.255.255')
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_not_enough_cluster)
            def _should_fail_cluster_in_use():
                cluster.add_nodes(1, address_range_start=existing_address, address_range_end=existing_address, address_range_netmask='255.255.255.255')
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_cluster_in_use)
        finally:
            cluster.destroy(quick_destroy=True)

    def test_bad_add_node_ip_validation_gce(self):
        if not self.create_clusters:
            self.skipTest("skipping full cluster create tests for GCE")
        if not self.gce['enabled']:
            self.skipTest("skipping test for GCE")
        service = self.mk_gce_service()

        instances = service.get_instances(self.gce['existing'])
        existing_address = service.ip(instances[0])

        name = 'vfxtpy-unittest-{}'.format(int(time.time()))
        cluster = Cluster.create(service, self.gce['instance_type'], name, 'adminpass', root_image=self.gce['vfxt_image'], size=3, wait_for_state='yellow', tags=['unittest'], metadata={'vfxtpy-unittest': 'auto'})
        try:
            def _should_fail_instance_in_use():
                cluster.add_nodes(1, instance_addresses=[existing_address])
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_instance_in_use)
            def _should_fail_not_enough_instance():
                cluster.add_nodes(2, instance_addresses=[existing_address])
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_not_enough_instance)
            def _should_fail_not_enough_cluster():
                cluster.add_nodes(2, address_range_start=existing_address, address_range_end=existing_address, address_range_netmask='255.255.255.255')
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_not_enough_cluster)
            def _should_fail_cluster_in_use():
                cluster.add_nodes(1, address_range_start=existing_address, address_range_end=existing_address, address_range_netmask='255.255.255.255')
                raise Exception("test did not fail")
            self.assertRaises(vFXT.service.vFXTConfigurationException, _should_fail_cluster_in_use)
        finally:
            cluster.destroy(quick_destroy=True)


if __name__ == '__main__':
    unittest.main()
