"""
MIT License

Copyright (c) 2020-2022 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import struct
import socket
import netaddr
import requests
import netifaces

from scapy.all import *
from pydantic.utils import deep_update


class Net(object):
    """ Main of pex.net module.

    This main of pex.net module is intended for providing some
    implementations of various network tools.
    """

    def __init__(self) -> None:
        super().__init__()

        self.srp_timeout = 5
        self.sr1_timeout = 5
        self.sr_timeout = 3

        self.os_ttl = {
            0x3c: 'macos',
            0x40: 'linux',
            0xff: 'solaris',
            0x80: 'windows'
        }

        self.macdb = 'https://macvendors.co/api/'

        self.result = {}

    @staticmethod
    def get_gateways() -> list:
        """ Get all network interfaces available on the system.

        :return list: network gateways available on the system
        """

        gateways = []

        ifaces = netifaces.interfaces()
        for iface in ifaces:
            addrs = netifaces.ifaddresses(iface)

            if socket.AF_INET in addrs:
                addrs = addrs[socket.AF_INET][0]

                if 'addr' in addrs and 'netmask' in addrs:
                    gateways.append(str(netaddr.IPNetwork(
                        '%s/%s' % (addrs['addr'], addrs['netmask']))
                    ))

        return gateways

    def get_icmp_hosts(self, gateway: str) -> list:
        """ Get hosts from gateway using ICMP scanning.

        :param str gateway: gateway to get hosts from
        :return list: hosts
        """

        hosts = []

        packet = IP(dst=gateway) / ICMP()
        response = sr(packet, timeout=self.sr_timeout, verbose=False)[0]

        for _, recv in response:
            hosts.append(recv.src)

        return hosts

    def get_arp_hosts(self, gateway: str) -> list:
        """ Get hosts and MACs from gateway using ARP scanning.

        :param str gateway: gateway to get hosts and MACs from
        :return list: hosts and MACs
        """

        hosts = []

        arp = ARP(pdst=gateway)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")

        response = srp(ether / arp, timeout=self.srp_timeout, verbose=False)[0]

        if response:
            for _, recv in response:
                hosts.append((recv.psrc, recv.hwsrc))

        return hosts

    @staticmethod
    def get_ports(host: str, start: int = 0, end: int = 65535) -> dict:
        """ Scan host for opened ports.

        :param str host: host to scan for opened ports
        :param int start: first port
        :param int end: final port
        :return dict: dictionary of port and service name
        """

        ports = {}

        for port in range(start, end+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(0.5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

            connected = sock.connect_ex((host, port)) == 0
            sock.close()

            if connected:
                try:
                    name = socket.getservbyport(port)
                except Exception:
                    name = 'unidentified'

                ports.update({port: name})

        return ports

    def get_vendor(self, mac: str) -> str:
        """ Get vendor by MAC address.

        :param str mac: MAC address
        :return str: vendor name
        """

        try:
            return requests.get(self.macdb + mac).json()['result']['company']
        except Exception:
            return 'unidentified'

    @staticmethod
    def get_dns(host: str) -> str:
        """ Get local DNS name by host.

        :param str host: host to get local DNS name by
        :return str: local DNS name
        """

        try:
            return socket.gethostbyaddr(host)[0]
        except Exception:
            return 'unidentified'

    def get_platform(self, host: str) -> str:
        """ Detect platform by host.

        :param str host: host to detect platform by
        :return str: platform name
        """

        pack = IP(dst=host) / ICMP()
        response = sr1(pack, timeout=self.sr1_timeout, verbose=False)

        if response:
            if IP in response:
                ttl = response.getlayer(IP).ttl

                if ttl in self.os_ttl:
                    return self.os_ttl[ttl]

        return 'unix'

    def start_full_scan(self, gateway: str, scan: str = 'arp') -> None:
        """ Start network full scan.

        :param str gateway: gateway to start full scan for
        :param str scan: scan type (arp/icmp)
        :return None: None
        """

        if scan.lower() == 'arp':
            pairs = self.get_arp_hosts(gateway)
        elif scan.lower() == 'icmp':
            pairs = self.get_icmp_hosts(gateway)
        else:
            raise RuntimeError(f"Invalid scan type: {scan}!")

        for data in pairs:
            if isinstance(data, tuple):
                host = data[0]
                mac = data[1]

            else:
                host = ''
                mac = ''

            self.result = deep_update(self.result, {
                gateway: {
                    host: {
                        'mac': mac,
                        'vendor': self.get_vendor(mac),
                        'dns': self.get_dns(host),
                        'platform': self.get_platform(host),
                        'ports': {},
                    }
                }
            })

        for data in pairs:
            if isinstance(data, tuple):
                host = data[0]
            else:
                host = ''

            self.result = deep_update(self.result, {
                gateway: {
                    host: {
                        'ports': self.get_ports(host, end=1000)
                    }
                }
            })

    def full_scan_result(self) -> dict:
        """ Get network full scan result.

        :return dict: network full scan result
        """

        return self.result
