# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
'''
A utility class for working with network notation

Cookbook/examples:

n = Cidr('10.1.1.0/24')
n.start_address()
n.end_address()

for addr in n.addresses(): # generator
    print addr
addresses = n.addresses_list() # non-generator

if not n.contains('10.2.1.0'):
    pass
unused = n.available(count=1, used=['10.1.1.2','10.1.1.5'], contiguous=False)

int_val = Cidr.from_address('10.1.1.10')
str_val = Cidr.to_address(167837962)

addr_range_list = Cidr.expand_address_range('10.1.1.1','10.1.1.10')
'''

import struct
import socket
import logging
log = logging.getLogger(__name__)

class Cidr(object):
    '''A utility class for cidr notation'''
    def __init__(self, cidr, netmask=None):
        '''
            Arguments:
                cidr (str): x.x.x.x/x
        '''
        try:
            address, bits = cidr.split('/')
        except Exception as e:
            log.debug(e)
            if not netmask:
                raise ValueError("Must pass addr/prefix or 'addr','netmask'")
            address = cidr
            bits    = self.to_prefix(self.from_address(netmask))

        self.address    = address
        self.addr       = self.from_address(self.address)
        try:
            self.bits       = int(bits)
            self.mask       = (0xffffffff << (32 - int(self.bits))) & 0xffffffff
        except Exception as e:
            raise ValueError("Invalid prefix: {}".format(bits))
        self.netmask    = self.to_address(self.mask)

    def __str__(self):
        return "{}/{}".format(self.address, self.bits)
    def __repr__(self):
        return self.__str__()

    def start(self):
        ''' start of cidr block
            Returns: int
        '''
        return self.addr & ~(((1L << (32 - self.bits)) - 1))
    def end(self):
        ''' end of cidr block
            Returns: int
        '''
        return self.addr | (((1L << (32 - self.bits)) - 1))
    def size(self):
        '''Return the size (in IP addresses) of the cidr block
            Returns: int
        '''
        return 2**(32 - self.bits)
    def start_address(self):
        ''' start address of cidr block
            Returns: str
        '''
        return self.to_address(self.start())
    def end_address(self):
        ''' end address of cidr block
            Returns: str
        '''
        return self.to_address(self.end())

    def range(self):
        '''range of address values in the block
            Returns: list generator
        '''
        start = self.start()
        end   = self.end()
        for i in xrange(start, end + 1):
            yield i
    def range_list(self):
        '''Returns list from range'''
        return [n for n in self.range()]

    def addresses(self):
        '''range of address strings in the block
            Returns: list generator
        '''
        for i in self.range():
            yield self.to_address(i)
    def addresses_list(self):
        '''Returns list from addresses'''
        return [n for n in self.addresses()]

    def contains(self, ip):
        '''
            Arguments:
                ip (str)
            Returns: bool
        '''
        i = self.from_address(ip)
        return i & self.mask == self.addr & self.mask

    def available(self, count=1, contiguous=True, used=None, honor_reserves=True):
        '''Return a list of available addresses that are not in the used list

            Arguments:
                count (int): number of addresses
                contiguous (bool): list should be contiguous (defaults True)
                used (list, optional): list of used addresses to skip
                honor_reserves (bool, optional): skips first 4 addresses as well as the last
                    two address in the block.  These are commonly reserved by cloud providers.
            Returns: list
        '''
        used = set(used or [])
        # reserved addresses
        if honor_reserves:
            for offset in range(0, 4): # network, gateway, default services
                used.add(self.to_address(self.start() + offset))
            used.add(self.to_address(self.end() - 1)) # Second-to-last Reservation
            used.add(self.to_address(self.end())) # broadcast

        r = []
        for addr in self.addresses():
            if addr in used:
                # skip and reset our count
                if contiguous:
                    r = []
                continue
            r.append(addr)
            # if we have what we needed, return
            if len(r) == count:
                return r
        qualifier = 'contiguous ' if contiguous else ''
        raise Exception("Unable to find {} {}available addresses".format(count, qualifier))

    @classmethod
    def from_address(cls, addr):
        '''convert address string to integer value
            Arguments:
                ip (str)
            Returns: int
        '''
        try:
            return struct.unpack('!L', socket.inet_aton(str(addr)))[0]
        except Exception as e:
            log.debug(e)
            raise ValueError("Invalid address: {}".format(addr))
    @classmethod
    def to_address(cls, i):
        '''convert integer value to address string
            Arguments:
                i (int)
            Returns: str
        '''
        try:
            return socket.inet_ntoa(struct.pack('!L', int(i)))
        except Exception as e:
            log.debug(e)
            raise ValueError("Invalid address: {}".format(i))

    @classmethod
    def to_prefix(cls, mask):
        '''return the integer route prefix from an integer mask
            Arguments:
                mask (int)
            Returns: int
        '''
        return bin(mask).count('1') # hehe

    @classmethod
    def expand_address_range(cls, first, last):
        '''expand an address range from the first to the last
            Arguments:
                first (str): first address
                last (str): last address
            Returns: list
        '''
        r = []
        start = cls.from_address(first)
        stop  = cls.from_address(last)
        for offset in xrange(0, stop - start + 1):
            r.append(cls.to_address(start + offset))
        return r
