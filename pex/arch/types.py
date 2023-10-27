"""
MIT License

Copyright (c) 2020-2023 EntySec

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

from typing import Any, Optional


class Arch(object):
    """ Subclass of pex.arch.types module.

    This subclass of pex.arch.types module is intended for providing
    an implementation of architecture descriptor.
    """

    def __init__(self,
                 name: str,
                 endian: str = 'little',
                 bits: int = 64,
                 alter_names: list = [],
                 interpreter: Optional[str] = None,
                 sub_sets: list = []) -> None:
        """ Set architecture.

        :param str name: architecture name
        :param str endian: endian (little or big)
        :param list alter_names: architecture alternative names if presented
        :param int bits: bits (32 or 64)
        (e.g. mipsle - mipsle, ppc - powerpc)
        :param Optional[str] interpreter: interpreter if architecture is not a CPU
        (e.g. python, php)
        :param list sub_sets: sub sets of this platform
        (e.g. cpu may have a sub set of x64, x86, etc.)
        :return None: None
        """

        super().__init__()

        self.name = name.lower()
        self.endian = endian.lower()
        self.alter_names = alter_names
        self.bits = int(bits)
        self.interpreter = interpreter
        self.sub_sets = sub_sets

    def __len__(self) -> int:
        """ Get bits.

        :return int: number of bits (32 or 64)
        """

        return self.bits

    def __hash__(self) -> int:
        """ Make this architecture hashable.

        :return int: architecture hash
        """

        return hash(self.name)

    def __str__(self) -> str:
        """ Covert to string.

        :return str: architecture name
        """

        return self.name

    def __contains__(self, arch: Any) -> bool:
        """ Check if architecture is a sub set of current one.

        :param Any arch: can be architecture name of alternative name
        :return bool: True if contains else False
        """

        if isinstance(arch, str):
            if arch.lower() == self:
                return True

            for sub_set in self.sub_sets:
                if arch.lower() == sub_set:
                    return True

        elif isinstance(arch, self.__class__):
            if arch == self:
                return True

            for sub_set in self.sub_sets:
                if arch == sub_set or arch in sub_set:
                    return True

        return False

    def __eq__(self, arch: Any) -> bool:
        """ Check if architecture compatible with current one.

        :param Any arch: can be arch name or alternative name
        :return bool: True if compatible else False
        """

        if isinstance(arch, str):
            if arch.lower() == 'generic' or \
                    arch.lower() == self.name or \
                    arch in self.alter_names:
                return True

        elif isinstance(arch, self.__class__):
            if arch.name == 'generic' or \
                    arch.name == self.name or \
                    arch.name in self.alter_names:
                return True

        return False


ARCH_PYTHON = Arch(
    name='python',
    alter_names=['python3'],
    interpreter='python3'
)
ARCH_PHP = Arch(
    name='php',
    interpreter='php'
)
ARCH_PERL = Arch(
    name='perl',
    interpreter='perl'
)
ARCH_RUBY = Arch(
    name='ruby',
    interpreter='ruby'
)
ARCH_BASH = Arch(
    name='bash',
    interpreter='bash'
)
ARCH_APPLESCRIPT = Arch(
    name='applescript',
    alter_names=['osascript'],
    interpreter='osascript'
)
ARCH_X64 = Arch(
    name='x64',
    alter_names=['x86_64']
)
ARCH_X86 = Arch(
    name='x86',
    alter_names=['i386']
)
ARCH_AARCH64 = Arch(
    name='aarch64',
    alter_names=['arm64']
)
ARCH_ARMLE = Arch(
    name='armle',
    bits=32,
    alter_names=['armel']
)
ARCH_ARMBE = Arch(
    name='armbe',
    endian='big',
    bits=32,
    alter_names=['armeb']
)
ARCH_MIPSLE = Arch(
    name='mipsle',
    bits=32,
    alter_names=['mipsel']
)
ARCH_MIPSBE = Arch(
    name='mipsbe',
    endian='little',
    bits=32,
    alter_names=['mipseb']
)
ARCH_GENERIC = Arch(
    name='generic',
)
