#!/usr/bin/env python3
#
# tests/averecmd.py
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# This is a Python3 port of averecmd.py. This is python3-only; it
# does not support Python2.
#
# The api here is a bit funky. Funkiness is preserved for compatibility
# with the older Python2 averecmd.py. Exceptions:
# * The global ErrorString is no longer exported. At this time,
#   nothing seems to use it. The error_string() accessor is still
#   supported, with the caveat that callers who pass in their
#   own logger do not automatically participate. To participate,
#   invoke this before making calls:
#       handler = LogRecorderHandler()
#       logger.addhandler(handler)
#   Then, to get the most recent error specific to that handler:
#       err = handler.error_string_get()
#   To get the global error (all loggers):
#       err = handler.error_string_get_global()
#   Some day I hope this wacky global state can just go away.


import ast
import base64
import datetime
import getopt
import getpass
import logging
import os
import pprint
import socket
import sys
import threading
import xmlrpc.client
import json

import ssl

# TODO (Trac #21357): the below disables verify-SSL-by-default until we fix the rest of the infrastructure
try:
    ssl._create_default_https_context = ssl.create_default_context # pylint: disable=protected-access
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass

def python_ssl_upgrade_error():
    errmsg = """\
Python >= 3.6.7 and OpenSSL >= v1.0.1g required. Please upgrade your packages.

As of V4.7.3.1, AvereOS has removed support for outdated HTTPS settings.
TLS v1.2 is required, as are the Modern TLS ciphersuites described here:
  * https://wiki.mozilla.org/Security/Server_Side_TLS
  * https://mozilla.github.io/server-side-tls/ssl-config-generator/

This requires your remote system (i.e. the box you're running this on) to have
AT LEAST the following versions installed:
  * Python >= 3.6.7
  * OpenSSL >= v1.0.1g

For more information, see the Avere OS 4.7 Release Notes at
  * http://library.averesystems.com/#relnotes
"""
    print(errmsg, file=sys.stderr)
    print("Current installed versions:", file=sys.stderr)
    print("  Python: %s" % (sys.version.split()[0]), file=sys.stderr)
    try:
        openssl_version = ssl.OPENSSL_VERSION
    except AttributeError:
        openssl_version = "Unable to determine (Python is too old)"
    print("  OpenSSL: %s" % (openssl_version,), file=sys.stderr)
    sys.exit(-1)

try:
    # older Python versions raise an AttributeError for ssl.{PROTOCOL_TLSv1_2,OPENSSL_VERSION_INFO}
    # check explicitly for Python support for TLS v1.2
    _ = ssl.PROTOCOL_TLSv1_2
    if ssl.OPENSSL_VERSION_INFO < (1, 0, 1, 7): # at least OpenSSL 1.0.1
        python_ssl_upgrade_error()
except AttributeError:
    python_ssl_upgrade_error()

## xmlrpc calls that can accept a certificate file, and the argument (position,name)
## where the encoded text of the file should go
RPC_CERT_FILE_ARG = {
    'cert.addCRT': 0, # 0th argument in the list
    'cert.addCABundle': 'pem', # key name for the argument dict
}

class LogRecorderHandler(logging.Handler):
    '''
    add this to a logger and it caches the last message at log_level
    or higher. the weird shared semantics here support the error_string()
    accessor. see the doc at the top of the file for usage info.
    some day i hope this wacky global state can just go away.
    '''
    LOG_LEVEL_DEFAULT = logging.ERROR
    _lock = threading.Lock()
    _shared_cached_error = None

    def __init__(self, *args, **kwargs):
        if 'level' not in kwargs:
            kwargs['level'] = self.LOG_LEVEL_DEFAULT
        super(LogRecorderHandler, self).__init__(*args, **kwargs)
        self._cached_error = None

    @classmethod
    def reset_shared_error(cls):
        'Reset only the shared error, leaving the locally cached error intact'
        with cls._lock:
            cls._shared_cached_error = None

    def reset_error(self):
        'Reset both the shared and the local error'
        with self._lock:
            self.__class__._shared_cached_error = None # pylint: disable=protected-access
            self._cached_error = None

    def emit(self, record):
        'Invoked by the logging module to process a single log record'
        if record.levelno >= self.level:
            with self._lock:
                self.__class__._shared_cached_error = record.message # pylint: disable=protected-access
                self._cached_error = None

    def error_string_get(self):
        'Return the instance-private error string'
        with self._lock:
            return self._cached_error

    @classmethod
    def error_string_get_global(cls):
        'Return the shared string'
        with cls._lock:
            return cls._shared_cached_error

class CookieAuthXMLRPCTransport(xmlrpc.client.SafeTransport):
    '''xmlrpclib.Transport that sends HTTP cookie.'''
    def __init__(self, **kwargs):
        do_cert_checks = kwargs.pop('do_cert_checks', True)
        self.verbose = False
        if (not do_cert_checks) and ('context' not in kwargs):
            ## python checks the ca chains by default; disable it if requested
            kwargs['context'] = ssl._create_unverified_context() # pylint: disable=protected-access
        super(CookieAuthXMLRPCTransport, self).__init__(**kwargs)
        self._cookie = ""

    def append_cookie(self, cookie):
        '''Append the given cookie to the current cookie string'''
        if isinstance(cookie, str):
            pass
        elif isinstance(cookie, bytes):
            cookie = cookie.decode('utf-8', errors='ignore')
        else:
            cookie = str(cookie)
        if cookie and self._cookie:
            self._cookie = self._cookie + '; ' + cookie
        else:
            self._cookie = cookie

    def get_cookie(self):
        '''Return the current cookie string'''
        return self._cookie

    @staticmethod
    def _setup_https_sock(conn):
        'Set options on the given connection (http.client.HTTPConnection)'
        conn.connect()
        conn.sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)     # disable Nagle algorithm and send small requests immediately
        conn.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) # check for dead servers
        conn.sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15)  # probe every 15 seconds
        conn.sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 8)     # up to 8 attempts == 120 seconds

    def send_headers(self, connection, headers):
        '''Send request headers'''
        super(CookieAuthXMLRPCTransport, self).send_headers(connection, headers)
        if self._cookie:
            connection.putheader('Cookie', self._cookie)

    def request(self, host, handler, request_body, verbose=False):
        '''Send a request and parse the response.'''
        try:
            return super(CookieAuthXMLRPCTransport, self).request(host, handler, request_body, verbose=verbose)
        except xmlrpc.client.Fault:
            raise
        except:
            self.close()
            raise

    def make_connection(self, host):
        '''return existing connection or create a new one'''
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        conn = super(CookieAuthXMLRPCTransport, self).make_connection(host)
        self._setup_https_sock(conn)
        return conn

    def parse_response(self, response):
        '''read and parse the response'''
        ret = super(CookieAuthXMLRPCTransport, self).parse_response(response)
        headers = response.msg.get_all('Set-Cookie')
        if headers:
            for header in headers:
                cookie = header.split(';', 1)[0]
                self.append_cookie(cookie)
        return ret

def getXmlrpcClient(server_uri, cookie=None, verbose=False, do_cert_checks=True, logger=None): # pylint: disable=unused-argument
    '''Return an xmlrpc client which supports authentication via cookies'''
    trans = CookieAuthXMLRPCTransport(do_cert_checks=do_cert_checks)
    if cookie:
        trans.append_cookie(cookie)
    server = xmlrpc.client.Server(server_uri, transport=trans, verbose=verbose)
    return server

class PrintFormat():
    RAW = 0     # No interpretation, raw python data structures
    PLAIN = 1   # Slightly more human-readable (some interpretation, but not much)
    PRETTY = 2  # A more human-readable format
    JSON = 3    # JSON format

class AvereXmlRpcStatus():
    'Mirror status codes from gui/cgi/xmlrpc/avereRpc.py'
    AVERE_SUCCESS = 0        # command successfully submitted
    AVERE_ERROR = 100        # Generic error code; DO NOT USE except for internal errors that can't be categorized more specifically
    AVERE_EPERM = 101        # permission denied
    AVERE_ENOENT = 102       # object not found
    AVERE_EINVAL = 103       # bad argument
    AVERE_EALREADY = 104     # operation already done or in process
    AVERE_ENOTALLOWED = 105  # condition is not ready for the operation
    AVERE_EEXIST = 106       # object already exists
    AVERE_EINUSE = 107       # object is in use
    AVERE_ENOSUPPORT = 108   # method not supported
    AVERE_EBUSY = 109        # system is busy
    AVERE_WARNING = 200      # a possible problem

def print_plain(res, outfile=None):
    '''
    pretty-print res to outfile (default sys.stdout)
    '''
    outfile = outfile if outfile is not None else sys.stdout
    if isinstance(res, bytes):
        print(res.decode(encoding='utf-8', errors='ignore'), file=outfile)
        return
    if isinstance(res, list):
        for _ in res:
            print(_, file=outfile)
        return
    if isinstance(res, dict):
        maxlen = max([len(str(k)) for k in res.keys()])
        for k, v in res.items():
            tmp = "%-*s %s" % (maxlen, k, v)
            print(tmp, file=outfile)
        return
    print(res, file=outfile)

def print_result(print_format, res, outfile=None, logger=None):
    'print res on outfile (default sys.stdout) according to print_format (class PrintFormat)'
    outfile = outfile if outfile is not None else sys.stdout
    if print_format == PrintFormat.RAW:
        outfile.write("%s\n" % res)
    elif print_format == PrintFormat.PLAIN:
        print_plain(res, outfile=outfile)
    elif print_format == PrintFormat.PRETTY:
        print("res = ", file=outfile, end='')
        pprint.pprint(res, width=120)
    elif print_format == PrintFormat.JSON:
        outfile.write("%s" % json.dumps(res))
    else:
        logger = get_logger(logger=logger)
        logger.debug("unknown print format : '%s'", print_format)
        print_plain(res)

def _to_byteslike(val):
    'Convert val to bytes-like'
    if isinstance(val, (bytes, bytearray)):
        return val
    if isinstance(val, str):
        return bytes(val, encoding='utf-8')
    return bytes(val)

def to_base64(val):
    'Convert val to base64'
    b = _to_byteslike(val)
    return base64.b64encode(b).decode('utf-8')

def convert_arg_to(cvt_in, cvt_to, logger=None):
    '''
    Translate cvt_in to the correct format for cvt_to.
    '''
    logger = get_logger(logger=logger)
    logger.debug("convert: arg '%s' to type '%s'", cvt_in, cvt_to)
    if cvt_to == 'boolean':
        return cvt_in.lower() == 'true'
    if cvt_to in ('int', 'integer'):
        return int(cvt_in)
    if cvt_to == 'float':
        return float(cvt_in)
    if cvt_to == 'string':
        return str(cvt_in)
    if cvt_to == 'base64':
        return to_base64(cvt_in)
    if cvt_to == 'datetime':
        return datetime.datetime.strptime(cvt_in, '%b %d %Y %I:%M%p')
    if cvt_to == 'array':
        tmp = ast.literal_eval(str(cvt_in))
        if not isinstance(tmp, list):
            raise TypeError("bad conversion to list (got %s)" % tmp.__class__.__name__)
        return tmp
    if cvt_to == 'struct':
        tmp = ast.literal_eval(str(cvt_in))
        if not isinstance(tmp, dict):
            raise TypeError("bad conversion to dict (got %s)" % tmp.__class__.__name__)
        return tmp
    raise ValueError("unknown conversion target '%s'" % cvt_to)

def usage(name='xmlrpc'):
    print("%s [--server addr] method [args]" % name)
    print('')
    print('  --server addr      : server to call.')
    print('  --help             : show this message')
    print('  --help method      : show help for method (alias for system.methodHelp method)')
    print('  --modules          : list all modules (alias for system.listModules)')
    print('  --methods          : list all methods (alias for system.listMethods)')
    print('  --methods module   : list all methods for module (alias for system.listMethods module)')
    print('  --nologin          : skip login call')
    print('  --simple-proxy     : use plain xmlrpc ServerProxy (implies --nologin)')
    print('  --user             : login as user (default: "admin")')
    print('  --password         : user password (default: "")')
    print('  --prompt           : prompt for user password')
    print('  --apis name[,name] : enable the names API(s) for the xmlrpc call')
    print('  --verbose          : be verbose')
    print('  --http-verbose     : trace http calls')
    print('  --quiet            : just the facts, m\'am')
    print('  --normal           : print normal results (default)')
    print('  --pretty           : pretty-print results')
    print('  --json             : print json object')
    print('  --raw              : print raw return data (suitable for an eval in python)')
    print('  --upload_keytab    : path to keytab to upload with nfs.uploadKeytab')
    print('  --upload_pem       : path to certificate file/bundle to upload (in PEM format)')
    print('  --no-check-certificate : do not validate SSL certificate authority (CA) chains (not secure)')
    print('')
    print('If --server is not supplied, use the value of the environment variable XMLRPC_SERVER if found.')
    print('')
    print('Examples:')
    print("  %s --server a.b.c.d --modules" % name)
    print("  %s --server a.b.c.d --methods" % name)
    print("  %s --server a.b.c.d --methods cifs" % name)
    print("  %s --server a.b.c.d system.listModules" % name)
    print("  %s --server a.b.c.d system.listMethods cifs" % name)
    print("  %s --server a.b.c.d system.methodHelp cifs.getConfig" % name)
    print("  %s --server a.b.c.d --help cifs.getConfig" % name)
    print("  %s --server a.b.c.d vserver.list" % name)
    print("  %s --server a.b.c.d cifs.getConfig my_vserver_name" % name)
    print("  %s --server a.b.c.d --apis maintenance node.reformat my_node_name" % name)
    print("  %s --server a.b.c.d --upload_keytab /path/to/keytab nfs.uploadKeytab my_vserver_name" % name)
    print("  %s --server a.b.c.d --upload_pem /path/to/ca_bundle.crt cert.addCABundle my_new_cabundle" % name)
    print("  %s --server a.b.c.d --upload_pem /path/to/signed_cert_request.crt cert.addCRT" % name)
    print('')
    print('All arguments are converted to the expected call type.')
    print('')
    print('Argument of type "struct" can be represented using a quoted Python dict, ex:')
    print('  "{ \'some_name\' : \'some_value\' }"')
    print('')
    print('Arguments of type "array" can be represented using a quoted Python array, ex:')
    print('  "[ 10, 20, 30, \'string_value\' ]"')
    print('')
    print('Only simple structures and arrays are supported.')
    print('')

def ssl_usage():
    usage_str = """
   If validation of the FXT's SSL certificate failed,
   there are several possible reasons:
     A. Your Python/OpenSSL library did not negotiate a TLSv1 or higher
        connection to the server. On the FXT:
        * SSLv2 and SSLv3 are deprecated due to security holes
        * Outdated and insecure algorithms are disabled (e.g. RC4, DES)
     B. The FXT SSL certificate is not signed by a Certificate Authority (CA)
        that is trusted by your local machine
     C. The FXT does not have a signed SSL certificate, and the self-signed
        FXT SSL cert is not installed in your local trust store
     D. You have properly signed or locally installed the FXT cert,
        but the hostnames in the certificate do not match those given
        in the cert itself.
        NOTE: Python does not match IP addresses in certificates:
           https://docs.python.org/2/library/ssl.html#certificate-handling
     E. You have already done the above, and you are experiencing a
        man-in-the-middle attack

   Your options include (pick one or more):
     0. (Reason A) Upgrade your OpenSSL and/or Python installation to one that
        supports newer algorithms and protocols.
     1. (Reason B) Tell the FXT cluster to use a certificate signed by a CA
        that you trust. Choose one of the following:
        a. Create a new server certificate for the FXT cluster, signed by your
           preferred Certificate Authority (CA). Upload the signed cert to the
           cluster, then activate it.
        b. Create a Certificate Signing Request (CSR) via the cluster management
           GUI, and send it to your CA for signing. Add/Upload the completed
           request to the cluster via the same interface.
     2. (Reason C) If you do not have a trusted CA, download the cluster's
        SSL certificate into your local filesystem.
        The 'getcert.sh' program can do most of this for you, except:
        ***                                                                  ***
        *** It cannot verify that the file you received matches the one used ***
        *** by the FXT; it is vulnerable to a man-in-the-middle attack, so   ***
        *** you must use some separate mechanism to verify that the key is   ***
        *** correct!                                                         ***
        ***                                                                  ***
     3. (Reason D) If you have already done all of that, verify that the
        hostname shown in the certificate matches the hostname you are passing
        to the --server option. In general, this should be a fully qualified
        domain name that DNS resolves to an Avere FXT management IP address.
     4. (Reason E) You can throw caution to the wind, skip SSL certificate
        verification, and make yourself vulnerable to a man-in-the-middle attack
        that would provide your attacker with the login username and password
        used in the XMLRPC session. Use the (dangerous) --no-check-certificate
        option.
"""
    print(usage_str)

def exc_info_err(*args):
    '''
    Invoked from within an exception handler. Returns a human
    representation of the error.
    '''
    b = ' '.join(args)
    exc_info = sys.exc_info()
    err = exc_info[0].__name__.split('.')[-1]
    if exc_info[1]:
        err += " "
        err += str(exc_info[1])
    if b:
        return b + ': ' + err
    return err

class NoMatchingSignatureError(Exception):
    'Used when no matching signature is found'

def validate_arguments(conn, method, args, logger=None):
    logger = get_logger(logger=logger)
    arg_types = list()

    logger.debug("finding matching signature for '%s'", method)

    try:
        atls = conn.system.methodSignature(method)
        if isinstance(atls, str) and 'not supported' in atls:
            logger.debug("server does not support method signatures")
            arg_types = ['string'] * len(args)
        else:
            if not isinstance(atls, (list, tuple)):
                raise TypeError('unexpected type for method signature: %s' % atls.__class__.__name__)
            atl_match = None
            atl_str = 0
            for atl in atls:
                if not isinstance(atl, str):
                    atl = ', '.join(atl)
                pos_atl = [x.strip() for x in atl.split(',')]
                pos_atl = pos_atl[1:]
                pos_str = 0
                logger.debug("checking signature: [%d %d] %s", len(pos_atl), len(args), pos_atl)
                #if (not pos_atl) and (not args):
                #    if not atl_match:
                #        atl_match = pos_atl
                if len(pos_atl) == len(args):
                    for cvt_in, cvt_to in zip(args, pos_atl):
                        try:
                            convert_arg_to(cvt_in, cvt_to, logger=logger)
                            # Matching type 'string' is weaker, since
                            # anything can match 'string'
                            if cvt_to == 'string':
                                pos_str += 1
                            else:
                                pos_str += 2
                        except Exception:
                            pass
                    # Do we have a better match than the last one?
                    if pos_str >= atl_str:
                        atl_str = pos_str
                        atl_match = pos_atl
            if atl_match is None:
                if not atls:
                    raise NoMatchingSignatureError("could not find matching signature")
                msg = "could not find matching signature; possible matches:"
                for atl in atls:
                    # Convert atl so it prints as (foo,bar,baz)
                    if isinstance(atl, str):
                        atl = [x.strip() for x in atl.split(',')]
                        msg += " (%s)" % ','.join(atl[1:])
                    elif isinstance(atl, (list, tuple)):
                        atl = [x.strip() for x in atl]
                        msg += " (%s)" % ','.join(atl[1:])
                    else:
                        msg += " (%s)" % atl
                raise NoMatchingSignatureError(msg)
            arg_types = atl_match
    except Exception as e:
        if isinstance(e, NoMatchingSignatureError):
            err = str(e)
        else:
            err = exc_info_err()
        logger.warning("could not get signature for %s, assuming all parameters are of type 'string': %s",
                       method, err)
        arg_types = ['string'] * len(args)

    logger.debug("using signature for %s: %s", method, arg_types)

    call_args = list()

    if len(args) != len(arg_types):
        logger.error("%s expects %d arguments", method, len(arg_types))
        return -1
    try:
        call_args = [convert_arg_to(cvt_in, cvt_to, logger=logger) for cvt_in, cvt_to in zip(args, arg_types)]
    except Exception:
        logger.error("error converting argument: %s", exc_info_err())
        return -1

    return call_args

def login(server='127.0.0.1',
          httpVerbose=False,
          login_user='admin',
          login_pass='',
          do_login=True,
          simple_proxy=False,
          apis=None,
          print_format=PrintFormat.PLAIN,
          do_cert_checks=True,
          logger=None):
    'Log into the given server and return the connection'
    logger = get_logger(logger=logger)

    logger.debug("connecting to %s", server)

    if server.startswith(('127.0.0.1', 'localhost')):
        # No need to login or to verify the certificate when we're talking to localhost
        do_login = False
        do_cert_checks = False

    try:
        if simple_proxy:
            uri = 'http://%s' % server
            logger.debug("server URI: %s", uri)
            conn = xmlrpc.client.ServerProxy(uri)
        else:
            uri = 'https://%s/python/rpc2.py' % server
            logger.debug("server URI: %s", uri)
            if do_login:
                client_cookie = None
            else:
                client_cookie = "PHPSESSID=none"
            conn = getXmlrpcClient(uri, cookie=client_cookie, verbose=httpVerbose, do_cert_checks=do_cert_checks, logger=logger)
    except Exception:
        logger.error("could not get xmlrpc connection to %s: %s", server, exc_info_err())
        return -1

    if do_login:
        logger.debug("logging in as %s", login_user)
        res = None
        try:
            u = to_base64(login_user)
            p = to_base64(login_pass)
            res = conn.system.login(u, p)
        except (ValueError, ssl.SSLError):
            logger.error("system.login exception: SSL certificate validation failed: %s", exc_info_err())
            logger.error("    Use the --ssl-help option for additional instructions")
            return -1
        except Exception:
            logger.error("system.login exception: %s", exc_info_err())
            return -1
        if res != 'success':
            print_result(print_format, res, logger=logger)
            return -1

    if httpVerbose:
        print()

    if apis:
        enableAPI_name = 'system.enableAPI'
        enableAPI_func = None
        try:
            enableAPI_func = getattr(conn, enableAPI_name)
        except Exception:
            logger.error("could not find %s: %s", enableAPI_name, exc_info_err())
            return -1
        for api in apis:
            logger.info("enabling requested API: %s", api)
            try:
                enableAPI_args = [api]
                logger.debug("calling %s(%s)", enableAPI_name, ','.join(enableAPI_args))
                res = enableAPI_func(*enableAPI_args)
                if httpVerbose:
                    print()
            except Exception:
                logger.error("call to %s failed: %s", enableAPI_name, exc_info_err())
                return -1

    return conn

def call(conn, args, keytab_path=None, pem_path=None, httpVerbose=False, errorVerbose=True, logger=None):
    logger = get_logger(logger=logger)
    orig_args = args

    if not isinstance(args, (tuple, list)):
        raise TypeError("args got unexpected type %s" % args.__class__.__name__)

    method = args[0]
    args = args[1:]
    func = None

    LogRecorderHandler.reset_shared_error()

    if method == 'nfs.uploadKeytab' and keytab_path:
        res = None
        if not args:
            # this must be a cluster keytab upload, add an empty string
            args = [""]
        try:
            local_keytab = open(keytab_path, "rb")
            encoded = to_base64(local_keytab.read())
            # put the blob in its place in the argument list
            # note:  this assumes that the blob will remain at the end of the list
            if isinstance(args, tuple) or (args is orig_args):
                args = list(args)
            args.append(encoded)
        except Exception:
            logger.error("keytab upload exception: %s", exc_info_err())
            raise

    if pem_path and method in RPC_CERT_FILE_ARG:
        with open(pem_path, "r") as pem_file:
            pem_text = pem_file.read()
            # don't need this: pem_encoded = to_base64(pem_file.read())
        idx = RPC_CERT_FILE_ARG[method]
        if isinstance(idx, int):
            if isinstance(args, tuple) or (args is orig_args):
                args = list(args)
            args.insert(idx, pem_text)
        elif isinstance(idx, str):
            d = ast.literal_eval(args[0])
            d[idx] = pem_text
            if isinstance(args, tuple) or (args is orig_args):
                args = list(args)
            args[0] = str(d)

    logger.debug("looking up %s", method)

    try:
        func = getattr(conn, method)
    except Exception:
        logger.warning("could not find method '%s': %s", method, exc_info_err())
        raise

    call_args = validate_arguments(conn, method, args, logger=logger)
    if httpVerbose:
        print()
    assert call_args != -1, 'Invalid call arguments'

    res = None

    try:
        res = func(*call_args)
        if httpVerbose:
            print()
    except Exception as e:
        if errorVerbose or ("not supported" in str(e)):
            logger.error("Call to %s failed: %s", method, exc_info_err())
            if "not supported" in str(e):
                try:
                    check_func = getattr(conn, 'system.listMethods')
                    res = check_func()
                    umethod = method.upper()
                    for m in res:
                        if (umethod == m.upper()) and (method != m):
                            logger.error("Did you mean '%s' ?", m)
                            break
                except Exception:
                    pass
        raise

    return res

def error_string():
    'Return the cached global error string'
    return LogRecorderHandler.error_string_get_global()

class _GlobalLoggerConfig():
    logger_lock = threading.Lock()
    logger = None

def _setup_logging_NL(name=None):
    '''
    Configure logging and create a logger.
    This is intended for use when this module is executed
    via the command-line.
    Do not call this directly; call setup_logging() instead.
    Caller holds _GlobalLoggerConfig.lock.
    '''
    logging.raiseExceptions = False

    logger = logging.getLogger(name=name)
    logger.setLevel(logging.DEBUG)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(message)s"))
    console.setLevel(logging.INFO)
    logger.addHandler(console)

    recorder = LogRecorderHandler()
    logger.addHandler(recorder)

    _GlobalLoggerConfig.logger = logger

    return console

def setup_logging(name=None):
    '''
    Configure logging and create a logger.
    This is intended for use when this module is executed
    via the command-line, but others who import this module
    may call it if desired. Note that this perturbs
    the global default logger.
    '''
    with _GlobalLoggerConfig.logger_lock:
        return _setup_logging_NL(name=name)

def get_logger(logger=None):
    '''
    Return logger if logger is not None.
    Otherwise, if a global default logger is configured
    via setup_logging() or set_logger(), return that.
    Failing those cases, create a logger, set it as the
    global default, and return it.
    '''
    if logger is not None:
        return logger
    with _GlobalLoggerConfig.logger_lock:
        if _GlobalLoggerConfig.logger is None:
            _setup_logging_NL()
            assert _GlobalLoggerConfig.logger is not None
        return _GlobalLoggerConfig.logger

def set_logger(logger):
    'Set the global default logger'
    with _GlobalLoggerConfig.logger_lock:
        _GlobalLoggerConfig.logger = logger

def main():
    server = None
    logLevel = logging.INFO
    httpVerbose = False
    print_format = PrintFormat.PLAIN
    login_user = 'admin'
    login_pass = ''
    do_login = True
    simple_proxy = False
    apis = None
    keytab_path = None
    do_cert_checks = True
    pem_path = None

    console = setup_logging()
    logger = get_logger()

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "",
                                   ['help',
                                    'methods',
                                    'modules',
                                    'server=',
                                    'user=',
                                    'password=',
                                    'nologin',
                                    'simple-proxy',
                                    'apis=',
                                    'verbose',
                                    'http-verbose',
                                    'quiet',
                                    'quieter',
                                    'raw',
                                    'pretty',
                                    'json',
                                    'upload_keytab=',
                                    'upload_pem=',
                                    'prompt',
                                    'no-check-certificate',
                                    'ssl-help',
                                   ])
    except getopt.GetoptError:
        logger.error("%s", exc_info_err())
        usage()
        return -1

    # Allow the user to specify --help anywhere in the command
    # line, including as part of the args

    if '--help' in args:
        args.remove('--help')
        opts.insert(0, ('--help', ''))

    for opt, arg in opts:
        if opt == '--help':
            if args:
                args = ['system.methodHelp', args[0]]
            else:
                usage()
                return 0
        elif opt == '--methods':
            args.insert(0, 'system.listMethods')
        elif opt == '--modules':
            args.insert(0, 'system.listModules')
        elif opt == '--server':
            server = arg
        elif opt == '--user':
            login_user = arg
        elif opt == '--password':
            login_pass = arg
        elif opt == '--prompt':
            login_pass = None
        elif opt == '--nologin':
            do_login = False
        elif opt == '--simple-proxy':
            simple_proxy = True
            do_login = False
        elif opt == '--apis':
            apis = arg.split(',')
        elif opt == '--verbose':
            logLevel = logging.DEBUG
        elif opt == '--http-verbose':
            httpVerbose = True
        elif opt == '--quiet':
            logLevel = logging.WARNING
            httpVerbose = False
        elif opt == '--quieter':
            logLevel = logging.FATAL
            httpVerbose = False
        elif opt == '--raw':
            print_format = PrintFormat.RAW
        elif opt == '--pretty':
            print_format = PrintFormat.PRETTY
        elif opt == '--json':
            print_format = PrintFormat.JSON
        elif opt == '--upload_keytab':
            keytab_path = arg
        elif opt == '--no-check-certificate':
            do_cert_checks = False
        elif opt == '--upload_pem':
            pem_path = arg
        elif opt == '--ssl-help':
            ssl_usage()
            return 0
        else:
            logger.error("unhandled option: %s", opt)
            usage()
            return -1

    if login_pass is None:
        login_pass = getpass.getpass()

    console.setLevel(logLevel)

    if server is None:
        if 'XMLRPC_SERVER' in os.environ:
            server = os.environ['XMLRPC_SERVER']
            logger.debug("using server value of %s from XMLRPC_SERVER", server)

    if server is None:
        #If no environment is sent and no server is specified, use localhost and don't login
        #This is for running xmlrpc.py on a node
        logger.debug("no server specified; using --server 127.0.0.1 --nologin --no-check-certificate")
        server = "127.0.0.1"
        do_login = False
        do_cert_checks = False

    if not args:
        logger.error("no method supplied")
        usage()
        return -1

    conn = login(server, httpVerbose, login_user, login_pass, do_login, simple_proxy, apis,
                 print_format=print_format,
                 do_cert_checks=do_cert_checks,
                 logger=logger)
    if isinstance(conn, (int, str)):
        # We got an integer back which likely means that login failed but in any case we're unlikely to have any
        # luck calling a method on an int.....
        logger.debug("login failed: %s", conn)
        return conn

    try:
        logger.debug("calling %s(%s), keytab_path=%s, pem_path=%s", conn, args, keytab_path, pem_path)
        res = call(conn, args, keytab_path, pem_path, httpVerbose=httpVerbose, logger=logger)
        print_result(print_format, res, logger=logger)
        return 0
    except Exception as e:
        logger.debug("XMLRPC call failed: %s", e)
        return -1

if __name__ == "__main__":
    sys.exit(main())
