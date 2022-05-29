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

from .casting import Casting


class Type:
    """ Subclass of pex.type module.

    This subclass of pex.type module is intended in providing
    some important constants and type casting methods.
    """

    casting = Casting()

    platforms = {
        'generic': [
            'unix',
            'linux',
            'aix',
            'bsd',
            'macos',
            'solaris',
            'apple_ios',
            'android',
            'windows'
        ],
        'xnu': [
            'macos',
            'apple_ios'
        ],
        'unix': [
            'unix',
            'linux',
            'aix',
            'bsd',
            'macos',
            'solaris',
            'apple_ios',
            'android'
        ],
        'windows': [
            'windows'
        ]
    }

    shells = {
        'sh': '/bin/sh',
        'bash': '/bin/bash',
        'ash': '/bin/ash',
        'ksh': '/bin/ksh'
    }

    architectures = {
        'generic': {
            'python': {
                'command': 'python3',
                'platforms': platforms['generic']
            },
            'php': {
                'command': 'php',
                'platforms': platforms['generic']
            },
            'perl': {
                'command': 'perl',
                'platforms': platforms['generic']
            },
            'ruby': {
                'command': 'ruby',
                'platforms': platforms['generic']
            },
            'bash': {
                'command': 'bash',
                'platforms': platforms['unix']
            },
            'sh': {
                'command': 'sh',
                'platforms': platforms['unix']
            },
            'ksh': {
                'command': 'ksh',
                'platforms': platforms['unix']
            },
            'applescript': {
                'command': 'osascript',
                'platforms': platforms['xnu']
            }
        },
        'cpu': [
            'x86',
            'x64',

            'aarch64',
            'armle',
            'armbe',

            'mips64'
            'mipsle',
            'mipsbe',

            'ppc',
            'ppc64',

            'sh4',

            'zarch',

            'sparc'
        ]
    }

    formats = {
        'macho': [
            'macos',
            'apple_ios'
        ],
        'elf': [
            'unix',
            'linux',
            'aix',
            'bsd',
            'solaris',
            'android'
        ],
        'pe': [
            'windows'
        ]
    }

    types = {
        'mac': casting.is_mac,
        'ip': casting.is_ip,
        'ipv4': casting.is_ipv4,
        'ipv6': casting.is_ipv6,
        'ipv4_range': casting.is_ipv4_range,
        'ipv6_range': casting.is_ipv6_range,
        'port': casting.is_port,
        'port_range': casting.is_port_range,
        'number': casting.is_number,
        'integer': casting.is_integer,
        'float': casting.is_float,
        'boolean': casting.is_boolean
    }
