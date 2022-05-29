#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import re


class Casting:
    """ Subclass of pex.type module.

    This subclass of pex.type module is intended in providing
    implementations of some type casting methods.
    """

    @staticmethod
    def is_mac(mac: str) -> bool:
        """ Check if string is a MAC address.

        :param str mac: string to check
        :return bool: True if string is a MAC address
        """

        regexp = r"^[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}:[a-f\d]{1,2}$"
        if re.match(regexp, mac.lower()):
            return True
        return False

    @staticmethod
    def is_ipv4(ipv4: str) -> bool:
        """ Check if string is an IPv4 address.

        :param str ipv4: string to check
        :return bool: True if string is an IPv4 address
        """

        regexp = "^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        if re.match(regexp, ipv4):
            return True
        return False

    @staticmethod
    def is_ipv6(ipv6: str) -> bool:
        """ Check if string is an IPv6 address.

        :param str ipv6: string to check
        :return bool: True if string is an IPv6 address
        """

        regexp = "^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%.*$"
        if re.match(regexp, ipv6):
            return True
        return False

    def is_ip(self, ip: str) -> bool:
        """ Check if string is an IPv4 or an IPv6 address.

        :param str ip: string to check
        :return bool: True if string is an IPv4 or an IPv6 address
        """

        if self.is_ipv4(ip) or self.is_ipv6(ip):
            return True
        return False

    def is_ipv4_cidr(self, ipv4_cidr: str) -> bool:
        """ Check if string is an IPv4 cidr.

        :param str ipv4_cidr: string to check
        :return bool: True if string is an IPv4 cidr
        """

        cidr = ipv4_cidr.split('/')

        if len(cidr) == 2:
            if self.is_ipv4(cidr[0]) and int(cidr[1]) in range(0, 32+1):
                return True
        return False

    def is_ipv6_cidr(self, ipv6_cidr: str) -> bool:
        """ Check if string is an IPv6 cidr.

        :param str ipv6_cidr: string to check
        :return bool: True if string is an IPv6 cidr
        """

        cidr = ipv6_cidr.split('/')

        if len(cidr) == 2:
            if self.is_ipv6(cidr[0]) and int(cidr[1]) in range(0, 64+1):
                return True
        return False

    def is_port(self, port: int) -> bool:
        """ Check if integer is a port.

        :param int port: integer to check
        :return bool: True if integer is a port
        """

        if self.is_integer(port):
            if 0 < int(port) <= 65535:
                return True
        return False

    def is_port_range(self, port_range: str) -> bool:
        """ Check if string is a port range.

        :param str port_range: string to check
        :return bool: True if string is a port range
        """

        value = port_range.split('-')

        if len(value) == 2:
            if int(value[0]) <= int(value[1]):
                if self.is_port(value[0]) and self.is_port(value[1]):
                    return True
        return False

    @staticmethod
    def is_integer(value):
        value = str(value)
        if value.isdigit():
            return True
        return False

    @staticmethod
    def is_float(value):
        value = str(value)
        if re.match(r'^-?\d+(?:\.\d+)$', value):
            return True
        return False

    def is_number(self, value):
        if self.is_integer(value) or self.is_float(value):
            return True
        return False

    @staticmethod
    def is_boolean(value):
        value = value.lower()
        if value in ['yes', 'no', 'y', 'n']:
            return True
        return False
