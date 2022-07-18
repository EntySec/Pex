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
import netifaces

from scapy.all import *
from mac_vendor_lookup import MacLookup
from pydantic.utils import deep_update


class Net:
    """ Main of pex.net module.

    This main of pex.net module is intended for providing some
    implementations of various network tools.
    """

    srp_timeout = 5
    sr1_timeout = 5

    os_ttl = {
        0x3c: 'macos',
        0x40: 'linux',
        0xff: 'solaris',
        0x80: 'windows'
    }

    macdb = MacLookup()
    macdb_updated = False

    result = {}

    @staticmethod
    def get_gateways() -> dict:
        """ Get all network interfaces available on the system.

        :return dict: network interfaces available on the system
        """

        gateways = {}

        ifaces = netifaces.interfaces()
        for iface in ifaces:
            addrs = netifaces.ifaddresses(iface)

            if socket.AF_INET in addrs:
                addrs = addrs[socket.AF_INET][0]

                gateways.update({
                    iface: str(netaddr.IPNetwork(
                        '%s/%s' % (addrs['addr'], addrs['netmask'])
                    ))
                })

        return gateways

    def get_hosts(self, gateway: str) -> list:
        """ Get hosts and MACs from gateway.

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
    def get_ports(host: str, start: int = 0, end: int = 65535, tech: str = 'f') -> dict:
        """ Scan host for opened ports.

        :param str host: host to scan for opened ports
        :param int start: first port
        :param int end: final port
        :param int tech: technique to use
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

        if not self.macdb_updated:
            self.macdb.update_vendors()
            self.macdb_updated = True

        try:
            return self.macdb.lookup(mac)
        except Exception:
            return 'unidentified'

    def get_dns(self, host: str) -> str:
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

    def start_full_scan(self, gateway: str, iface: str) -> None:
        """ Start network full scan.

        :param str gateway: gateway to start full scan for
        :param str iface: interface to start full scan on
        :return None: None
        """

        pairs = self.get_hosts(gateway)

        for host, mac in pairs:
            self.result = deep_update(self.result, {
                gateway: {
                    iface: {
                        host: {
                            'mac': mac,
                            'vendor': self.get_vendor(mac),
                            'dns': self.get_dns(host),
                            'platform': self.get_platform(host),
                            'ports': {},
                            'flaws': {}
                        }
                    }
                }
            })

        for host, _ in pairs:
            self.result = deep_update(self.result, {
                gateway: {
                    iface: {
                        host: {
                            'ports': self.get_ports(host, end=1000)
                        }
                    }
                }
            })

    def full_scan_result(self) -> dict:
        """ Get network full scan result.

        :return dict: network full scan result
        """

        return self.result
