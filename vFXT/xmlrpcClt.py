#!/usr/bin/env python
# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.

import httplib
import socket
import xmlrpclib
import errno
import sys

def _setup_https_sock(h, verbose):
    if verbose:
        h.set_debuglevel(1)
    h.connect()
    h.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)    # disable Nagle algorithm and send small requests immediately
    h.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) # check for dead servers
    h.sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15) # probe every 15 seconds
    h.sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 8)    # up to 8 attempts == 120 seconds

class CookieAuthXMLRPCTransport(xmlrpclib.SafeTransport):
    '''xmlrpclib.Transport that sends HTTP cookie.'''
    def __init__(self, use_datetime=0, do_cert_checks=True):
        if (not do_cert_checks) and (sys.hexversion > 0x2070900):
            ## Python 2.7.9 and greater checks the CA chains by default; disable it if requested
            import ssl
            ctx = ssl._create_unverified_context()
            xmlrpclib.SafeTransport.__init__(self, use_datetime=use_datetime, context=ctx)
        else:
            xmlrpclib.SafeTransport.__init__(self, use_datetime=use_datetime)
        self._cookie = ""
        # Test if the underlying mechanism is httplib.HTTP (used in Python 2.6
        # and before), or httplib.HTTPConnection (used in Python 2.7). In the
        # latter, a persistent connection is stored in self._connection.
        try:
            getattr(self, '_connection')
            self._has_httpconnection = True
        except AttributeError:
            self._has_httpconnection = False

    def send_host(self, connection, host):
        '''Send the Host: header and extra headers.
        Note that in 2.7, this doesn't actually send the Host: header, but we
        just want to send the Cookie: header, and this is the proper place to
        do it.

        '''
        xmlrpclib.SafeTransport.send_host(self, connection, host)
        if self._cookie:
            # Session cookie is set, send it
            connection.putheader('Cookie', self._cookie)

    def request(self, host, handler, request_body, verbose=0):
        '''Send a complete request and return a parsed response.'''
        if self._has_httpconnection:
            #retry request once if cached connection has gone cold
            for i in (0, 1):
                try:
                    return self.single_request(host, handler, request_body, verbose)
                except socket.error as e:
                    if i or e.errno not in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                        raise
                except httplib.BadStatusLine: #close after we sent request
                    if i:
                        raise
        else:
            h = self.make_connection(host)
            _setup_https_sock(h, verbose)
            self.send_request(h, handler, request_body)
            self.send_host(h, host)
            self.send_user_agent(h)
            self.send_content(h, request_body)
            errcode, errmsg, headers = h.getreply()
            if errcode != 200:
                raise xmlrpclib.ProtocolError(host + handler,
                                              errcode, errmsg,
                                              headers
                                              )
            cookie_header = headers.getheaders('Set-Cookie')
            if cookie_header:
                self._cookie = '; '.join(cookie_header)
            self.verbose = verbose # pylint: disable=attribute-defined-outside-init
            try:
                sock = h._conn.sock # pylint: disable=no-member
            except AttributeError:
                sock = None
            return self._parse_response(h.getfile(), sock) # pylint: disable=no-member

    def single_request(self, host, handler, request_body, verbose=0):
        '''Issue an XML-RPC request on a persistent HTTPConnection.'''
        h = self.make_connection(host)
        _setup_https_sock(h, verbose)

        try:
            self.send_request(h, handler, request_body)
            self.send_host(h, host)
            self.send_user_agent(h)
            self.send_content(h, request_body)

            response = h.getresponse(buffering=True)
            if response.status == 200:
                self.verbose = verbose # pylint: disable=attribute-defined-outside-init
                cookie_header = response.getheader('set-cookie')
                if cookie_header:
                    cookies = cookie_header.split(', ')
                    self._cookie = '; '.join(cookies)
                return self.parse_response(response)
        except xmlrpclib.Fault:
            raise
        except Exception:
            # All unexpected errors leave connection in
            # a strange state, so we clear it.
            self.close()
            raise

        #discard any response data and raise exception
        if response.getheader("content-length", 0):
            response.read()
        raise xmlrpclib.ProtocolError(host + handler,
                                      response.status, response.reason,
                                      response.msg,
                                      )

def getXmlrpcClientAndTransport(server_uri, verbose=False, do_cert_checks=True):
    '''Return an xmlrpc client which supports authentication via cookies'''
    trans = CookieAuthXMLRPCTransport(do_cert_checks=do_cert_checks)
    client = xmlrpclib.Server(server_uri, transport=trans, verbose=verbose)
    return trans, client

def getXmlrpcClient(server_uri, verbose=False, do_cert_checks=True):
    return getXmlrpcClientAndTransport(server_uri, verbose, do_cert_checks)[1]


def main():
    import code

    mgmt_ip  = None
    username = None
    password = None
    try:
        mgmt_ip  = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
    except Exception:
        print "Arguments required: [mgmt ip] [username] [password]"
        return

    s = getXmlrpcClient("http://{0}/cgi-bin/rpc2.py".format(mgmt_ip), do_cert_checks=False)
    res = s.system.login(username.encode('base64'), password.encode('base64'))
    if res != 'success':
        raise Exception(res)

    code.interact(local=locals())


if __name__ == '__main__':
    main()
