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
import logging
import unittest
import tests.vFXTTestCase
from vFXT.cidr import Cidr

logging.basicConfig()

class cidr_test(tests.vFXTTestCase.Base):

    def test__init__(self):
        c = Cidr('10.1.1.0/24')
        self.assertIsInstance(c, Cidr)

        c = Cidr('10.1.1.0', '255.255.255.0')
        self.assertIsInstance(c, Cidr)

        self.assertRaises(ValueError, Cidr, ('10.1.1.0/240'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0/bad'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0/'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0', 'bad'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0', '1024.1024.1024.0'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0', '-255.-255.-255.0'))
        self.assertRaises(ValueError, Cidr, ('10.1.1.0', '-1'))
        self.assertRaises(ValueError, Cidr, (''))

    def test_start(self):
        c = Cidr('10.1.1.0/24')
        self.assertTrue(c.start_address() == '10.1.1.0')
        c = Cidr('10.1.1.0/16')
        self.assertTrue(c.start_address() == '10.1.0.0')
        c = Cidr('10.1.1.0/8')
        self.assertTrue(c.start_address() == '10.0.0.0')
        c = Cidr('10.1.1.1/32')
        self.assertTrue(c.start_address() == '10.1.1.1')

    def test_end(self):
        c = Cidr('10.1.1.0/24')
        self.assertTrue(c.end_address() == '10.1.1.255')
        c = Cidr('10.1.1.0/16')
        self.assertTrue(c.end_address() == '10.1.255.255')
        c = Cidr('10.1.1.0/8')
        self.assertTrue(c.end_address() == '10.255.255.255')
        c = Cidr('10.1.1.1/32')
        self.assertTrue(c.end_address() == '10.1.1.1')

    def test_range(self):
        c = Cidr('10.1.1.0/24')
        self.assertTrue(len(c.range_list()) == 256)
        c = Cidr('10.1.1.0/16')
        self.assertTrue(len(c.range_list()) == 65536)
        #c = Cidr('10.1.1.0/8')
        #self.assertTrue(len(c.range_list()) == 16777216)
        c = Cidr('10.1.1.0/32')
        self.assertTrue(len(c.range_list()) == 1)

    def test_addresses(self):
        c = Cidr('10.1.1.0/24')
        self.assertTrue(len(c.addresses_list()) == 256)
        c = Cidr('10.1.1.0/16')
        self.assertTrue(len(c.addresses_list()) == 65536)
        #c = Cidr('10.1.1.0/8')
        #self.assertTrue(len(c.addresses_list()) == 16777216)
        c = Cidr('10.1.1.0/32')
        self.assertTrue(len(c.addresses_list()) == 1)

    def test_contains(self):
        c = Cidr('10.1.1.0/24')
        self.assertTrue(c.contains('10.1.1.200'))
        self.assertFalse(c.contains('10.1.2.200'))
        c = Cidr('10.1.1.0/16')
        self.assertTrue(c.contains('10.1.200.200'))
        self.assertFalse(c.contains('10.0.2.200'))
        c = Cidr('10.1.1.0/8')
        self.assertTrue(c.contains('10.100.200.200'))
        self.assertFalse(c.contains('12.0.2.200'))
        c = Cidr('10.1.1.100/32')
        self.assertTrue(c.contains('10.1.1.100'))
        self.assertFalse(c.contains('10.1.1.200'))

    def test_from_address(self):
        self.assertTrue(Cidr.from_address('10.1.1.10') == 167837962)
        self.assertRaises(ValueError, Cidr.from_address, 'bad')
        self.assertRaises(ValueError, Cidr.from_address, '-1')
        self.assertRaises(ValueError, Cidr.from_address, '500.500.500.500')
    def test_to_address(self):
        self.assertTrue(Cidr.to_address(167837962) == '10.1.1.10')
        self.assertTrue(Cidr.to_address(4294967295) == '255.255.255.255')
        self.assertTrue(Cidr.to_address(0) == '0.0.0.0')
        self.assertRaises(ValueError, Cidr.to_address, 'bad')
        self.assertRaises(ValueError, Cidr.to_address, '-1')
        self.assertRaises(ValueError, Cidr.to_address, 4294967296)

    def test_to_prefix(self):
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('254.0.0.0')) == 7)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.0.0.0')) == 8)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.254.0.0')) == 15)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.0.0')) == 16)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.240.0')) == 20)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.255.0')) == 24)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.255.128')) == 25)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.255.252')) == 30)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.255.254')) == 31)
        self.assertTrue(Cidr.to_prefix(Cidr.from_address('255.255.255.255')) == 32)

    def test_expand_address_range(self):
        self.assertTrue(cmp(Cidr.expand_address_range('10.1.1.1', '10.1.1.3'), ['10.1.1.1', '10.1.1.2', '10.1.1.3']) == 0)
        self.assertFalse(cmp(Cidr.expand_address_range('10.1.1.1', '10.1.1.7'), ['10.1.1.1', '10.1.1.2', '10.1.1.3']) == 0)
        self.assertRaises(ValueError, Cidr.expand_address_range, '10.1.1.1', 'bad')
        self.assertTrue(cmp(Cidr.expand_address_range('10.1.1.1', '10.1.0.3'), []) == 0)

    def test_available(self):
        c = Cidr('10.1.1.200/28')
        self.assertTrue(len(c.addresses_list()) == 16)
        used = ['10.1.1.196', '10.1.1.200']
        self.assertTrue(cmp(c.available(used=used), ['10.1.1.197']) == 0)
        self.assertTrue(cmp(c.available(count=1, used=used), ['10.1.1.197']) == 0)
        self.assertTrue(cmp(c.available(count=5, used=used), ['10.1.1.201', '10.1.1.202', '10.1.1.203', '10.1.1.204', '10.1.1.205']) == 0)
        self.assertTrue(cmp(c.available(count=3, used=used, contiguous=False), ['10.1.1.197', '10.1.1.198', '10.1.1.199']) == 0)
        self.assertRaises(Exception, c.available, count=16, used=used)
        self.assertRaises(Exception, c.available, count=16)
        self.assertTrue(len(c.available(count=16, honor_reserves=False)) == 16)

    def test_display(self):
        c = Cidr('10.1.1.200/28')
        self.assertTrue('{}'.format(c))

if __name__ == '__main__':
    unittest.main()
