"""
MIT License

Copyright (c) 2020-2024 EntySec

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

from typing import Tuple
from .casting import Casting

from pex.arch.types import *
from pex.platform.types import *


class Type(object):
    """ Main class of pex.type module.

    This main class of pex.type module is intended for providing
    some important constants and type casting methods.
    """

    def __init__(self) -> None:
        super().__init__()

        self.casting = Casting()

        self.types = {
            'mac': self.casting.is_mac,
            'ip': self.casting.is_ip,
            'ipv4': self.casting.is_ipv4,
            'ipv6': self.casting.is_ipv6,
            'ipv4_cidr': self.casting.is_ipv4_cidr,
            'ipv6_cidr': self.casting.is_ipv6_cidr,
            'port': self.casting.is_port,
            'port_range': self.casting.is_port_range,
            'number': self.casting.is_number,
            'integer': self.casting.is_integer,
            'float': self.casting.is_float,
            'boolean': self.casting.is_boolean
        }

    @staticmethod
    def from_target(target: str) -> Tuple[Platform, Arch]:
        """ Normalize target tuple.

        :param str target: target (e.g. aarch64-linux-musl)
        :return Tuple[Platform, Arch]: tuple of platform and arch
        :raises RuntimeError: with trailing error message
        """

        target = target.split('-')

        if len(target) != 3:
            raise RuntimeError("Invalid target tuple provided!")

        platforms = []
        arches = []

        for name, item in globals().items():
            if name.startswith('OS'):
                platforms.append(item)
            if name.startswith('ARCH'):
                arches.append(item)

        platform = OS_GENERIC
        arch = ARCH_GENERIC

        if target[1] in platforms:
            platform = platforms[platforms.index(target[1])]
        if target[0] in arches:
            arch = arches[arches.index(target[0])]

        return platform, arch
