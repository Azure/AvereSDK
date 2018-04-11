#!/usr/bin/python
# Copyright (c) 2015-2018 Avere Systems, Inc.  All Rights Reserved.
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
import logging

from vFXT.cluster import Cluster
import vFXT.service
import tests.vFXTTestCase

logging.basicConfig()
log = logging.getLogger(__name__)

class Cluster_test(tests.vFXTTestCase.Base):

    def setUp(self):
        tests.vFXTTestCase.Base.setUp(self)
        if not self.create_clusters:
            self.skipTest("skipping tests for cluster creation")


    def test__init__aws(self):
        if not self.aws['enabled']:
            self.skipTest("skipping test for AWS")
        aws = self.mk_aws_service()
        self.assertIsInstance(aws, vFXT.aws.Service)
        cluster = Cluster(service=aws)
        self.assertIsInstance(cluster, Cluster)

    def _run_cluster_steps(self, cluster):
        service = cluster.service

        self.assertIsInstance(cluster, Cluster)
        self.assertTrue(cluster.is_on())
        self.assertTrue(len(cluster.nodes) == 3)

        self.assertTrue(cluster.xmlrpc().cluster.get())

        # verify we can load the cluster and get the same info back
        loaded = Cluster.load(service, mgmt_ip=cluster.mgmt_ip, admin_password=cluster.admin_password)
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
        cluster.make_test_bucket(cluster.name)
        self.assertTrue(cluster.name in cluster.xmlrpc().corefiler.list())
        cluster.add_vserver_junction('vserver', cluster.name)

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

        cluster.telemetry()

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

    def test_bad_cluster_name(self):
        gce = self.mk_gce_service()
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, gce, self.gce['instance_type'], '', 'adminpass')
        self.assertRaises(vFXT.service.vFXTConfigurationException, Cluster.create, gce, self.gce['instance_type'], '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890', 'adminpass')


if __name__ == '__main__':
    unittest.main()
