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
import os
import tempfile

import vFXT.service
import tests.vFXTTestCase

logging.basicConfig()

class service_test(tests.vFXTTestCase.Base):

    def test_ShelveError(self):
        self.assertTrue(isinstance(vFXT.service.ShelveErrors(), dict))
        self.assertTrue(vFXT.service.ShelveErrors('k1:v1;k2:v2'))
        self.assertTrue('{}'.format(vFXT.service.ShelveErrors('k:v')))

    def test_backoff(self):
        self.assertTrue(vFXT.service.backoff(1) >= 2)
        self.assertTrue(vFXT.service.backoff(2) >= 4)
        self.assertTrue(vFXT.service.backoff(3) >= 8)
        self.assertTrue(vFXT.service.backoff(4) >= 16)
        self.assertTrue(vFXT.service.backoff(5) == vFXT.service.MAX_ERRORTIME) # 30

    def test_validate_proxy(self):
        self.assertRaises(vFXT.service.vFXTConfigurationException, vFXT.service.validate_proxy, '0')
        self.assertRaises(vFXT.service.vFXTConfigurationException, vFXT.service.validate_proxy, 'http')
        self.assertTrue(vFXT.service.validate_proxy('http://host:80'))
        self.assertTrue(vFXT.service.validate_proxy('https://host'))
        self.assertTrue(vFXT.service.validate_proxy('https://host:443'))
        self.assertTrue(vFXT.service.validate_proxy('http://user:pass@host'))
        self.assertTrue(vFXT.service.validate_proxy('http://user:pass@host:80'))

    def test_gethostbyname(self):
        self.assertTrue(vFXT.service.gethostbyname('www.google.com'))
        self.assertTrue(vFXT.service.gethostbyname('127.0.0.1'))

        import socket
        self.assertRaises(socket.gaierror, vFXT.service.gethostbyname, '-')

    def test_url_fetch(self):
        fd, name = tempfile.mkstemp()
        os.close(fd)
        os.unlink(name)
        try:
            s = vFXT.service.ServiceBase()
            s.url_fetch('http://www.google.com', name)
        finally:
            try:
                os.unlink(name)
            except Exception: pass


if __name__ == '__main__':
    unittest.main()
