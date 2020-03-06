#!/usr/bin/env python
# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
import base64
import logging
import requests
import socket
import ssl
import sys
import xmlrpc.client

requests.packages.urllib3.disable_warnings() # pylint: disable=no-member
logging.getLogger('urllib3').setLevel(logging.WARNING)

class RequestsTransport(xmlrpc.client.SafeTransport):

    class CustomAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs): #pylint: disable=arguments-differ
            kwargs['socket_options'] = [
                (socket.SOL_TCP, socket.TCP_NODELAY, 1),     # disable Nagle algorithm and send small requests immediately
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1), # check for dead servers
                (socket.SOL_TCP, socket.TCP_KEEPINTVL, 15),  # probe every 15 seconds
                (socket.SOL_TCP, socket.TCP_KEEPCNT, 8),     # up to 8 attempts == 120 seconds
            ]
            super(RequestsTransport.CustomAdapter, self).init_poolmanager(*args, **kwargs)

    def __init__(self, use_datetime=0, do_cert_checks=True):
        xmlrpc.client.SafeTransport.__init__(self, use_datetime=use_datetime)
        self._do_cert_checks = do_cert_checks
        socket_opts_adapter = self.CustomAdapter()
        self._requests_session = requests.session()
        self._requests_session.mount('http://', socket_opts_adapter)
        self._requests_session.mount('https://', socket_opts_adapter)
        self._requests_session.cookies.set('int64Representation', 'i8')
        self.verbose = False

    def request(self, host, handler, request_body, verbose=0):
        headers = {}
        url = 'https://{}/{}'.format(host, handler)

        response = self._requests_session.post(url, data=request_body, headers=headers, stream=True, cert=None, verify=self._do_cert_checks)
        response.raise_for_status()
        if verbose:
            logging.debug(response.headers)
        return self.parse_response(response.raw)

    @staticmethod
    def get_client_and_transport(server_uri, verbose=False, do_cert_checks=True):
        '''Return an xmlrpc client which supports authentication via cookies'''
        trans = RequestsTransport(do_cert_checks=do_cert_checks)
        client = xmlrpc.client.ServerProxy(server_uri, transport=trans, verbose=verbose)
        return trans, client

    @staticmethod
    def get_client(server_uri, verbose=False, do_cert_checks=True):
        return RequestsTransport.get_client_and_transport(server_uri, verbose, do_cert_checks)[1]

getXmlrpcClientAndTransport = RequestsTransport.get_client_and_transport
getXmlrpcClient = RequestsTransport.get_client

try:
    # older Python versions raise an AttributeError for ssl.{PROTOCOL_TLSv1_2,OPENSSL_VERSION_INFO}
    # check explicitly for Python support for TLS v1.2
    _ = ssl.PROTOCOL_TLSv1_2
    if ssl.OPENSSL_VERSION_INFO < (1,0,1,7): # at least OpenSSL 1.0.1
        raise Exception()
except Exception:
    try:
        openssl_version = ssl.OPENSSL_VERSION
    except AttributeError:
        openssl_version = "Unable to determine (Python is too old)"
    ERRMSG = """\
Python >= 2.7.9 and OpenSSL >= v1.0.1g required. Please upgrade your packages.

As of V4.7.3.1, AvereOS has removed support for outdated HTTPS settings.
TLS v1.2 is required, as are the Modern TLS ciphersuites described here:
  * https://wiki.mozilla.org/Security/Server_Side_TLS
  * https://mozilla.github.io/server-side-tls/ssl-config-generator/

This requires your remote system (i.e. the box you're running this on) to have
AT LEAST the following versions installed:
  * Python >= 2.7.9
  * OpenSSL >= v1.0.1g

For more information, see the Avere OS 4.7 Release Notes at
  * http://library.averesystems.com/#relnotes

Current installed versions:
    Python: {0}
    OpenSSL: {1}
"""
    logging.error(ERRMSG.format(sys.version.split()[0], openssl_version))
    sys.exit(-1)

if __name__ == '__main__':
    import code
    logging.basicConfig(level=logging.DEBUG)

    mgmt_ip  = None
    username = None
    password = None
    try:
        mgmt_ip  = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
    except Exception:
        logging.error("Arguments required: [mgmt ip] [username] [password]")
        sys.exit(1)

    logging.warning("Disabling certificate validation")
    rpc = RequestsTransport.get_client("https://{0}/python/rpc2.py".format(mgmt_ip), do_cert_checks=False, verbose=False)
    res = rpc.system.login(base64.b64encode(username.encode('utf-8')).decode(), base64.b64encode(password.encode('utf-8')).decode())
    if res != 'success':
        raise Exception(res)

    logging.info("XML-RPC client object is named rpc, issue methods with rpc.[method]([arguments])")
    code.interact(local=locals())
