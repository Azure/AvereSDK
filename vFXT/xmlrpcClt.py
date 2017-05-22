#!/usr/bin/env python
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
# Copyright (c) 2015-2017 Avere Systems, Inc.  All Rights Reserved.

import httplib
import socket
import xmlrpclib
import errno
import sys

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
                except socket.error, e:
                    if i or e.errno not in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE):
                        raise
                except httplib.BadStatusLine: #close after we sent request
                    if i:
                        raise
        else:
            h = self.make_connection(host)
            if verbose:
                h.set_debuglevel(1)
            self.send_request(h, handler, request_body)
            self.send_host(h, host)
            self.send_user_agent(h)
            self.send_content(h, request_body)
            errcode, errmsg, headers = h.getreply() # pylint: disable=no-member
            if errcode != 200:
                raise xmlrpclib.ProtocolError(
                    host + handler,
                    errcode, errmsg,
                    headers
                    )
            cookie_header = headers.getheaders('Set-Cookie')
            if cookie_header:
                self._cookie = '; '.join(cookie_header)
            self.verbose = verbose
            try:
                sock = h._conn.sock # pylint: disable=no-member
            except AttributeError:
                sock = None
            return self._parse_response(h.getfile(), sock) # pylint: disable=no-member

    def single_request(self, host, handler, request_body, verbose=0):
        '''Issue an XML-RPC request on a persistent HTTPConnection.'''
        h = self.make_connection(host)
        if verbose:
            h.set_debuglevel(1)

        try:
            self.send_request(h, handler, request_body)
            self.send_host(h, host)
            self.send_user_agent(h)
            self.send_content(h, request_body)

            response = h.getresponse(buffering=True)
            if response.status == 200:
                self.verbose = verbose
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
        if (response.getheader("content-length", 0)):
            response.read()
        raise xmlrpclib.ProtocolError(
            host + handler,
            response.status, response.reason,
            response.msg,
            )



def getXmlrpcClient(server_uri, verbose=False, do_cert_checks=True):
    '''Return an xmlrpc client which supports authentication via cookies'''
    trans = CookieAuthXMLRPCTransport(do_cert_checks=do_cert_checks)
    client = xmlrpclib.Server(server_uri, transport=trans, verbose=verbose)

    return client


def main():
    import xmlrpcClt
    import code
    import sys

    mgmt_ip  = None
    username = None
    password = None
    try:
        mgmt_ip  = sys.argv[1]
        username = sys.argv[2]
        password = sys.argv[3]
    except:
        print "Arguments required: [mgmt ip] [username] [password]"
        return

    s = xmlrpcClt.getXmlrpcClient("http://{0}/cgi-bin/rpc2.py".format(mgmt_ip), do_cert_checks=False)
    res = s.system.login(username.encode('base64'), password.encode('base64'))
    if res != 'success':
        raise Exception(res)

    code.interact(local=locals())


if __name__ == '__main__':
    main()
