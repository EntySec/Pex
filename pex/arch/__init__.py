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

from typing import Optional
from pex.type.dataset import DataSet


class Arch(DataSet):
    """ Subclass of pex.arch.types module.

    This subclass of pex.arch.types module is intended for providing
    an implementation of architecture set.
    """

    def __init__(self,
                 endian: str = 'little',
                 bits: int = 64,
                 interpreter: Optional[str] = None,
                 triplet: str = '*-*-*',
                 *args, **kwargs) -> None:
        """ Set architecture.

        :param str endian: endian (little or big)
        :param int bits: bits (32 or 64)
        (e.g. mipsle - mipsle, ppc - powerpc)
        :param Optional[str] interpreter: interpreter if architecture is not a CPU
        (e.g. python, php)
        :param str triplet: triplet glob expression
        :return None: None
        """

        super().__init__(*args, **kwargs)

        self.endian = endian.lower()
        self.bits = int(bits)
        self.interpreter = interpreter

    def __len__(self) -> int:
        """ Get bits.

        :return int: number of bits (32 or 64)
        """

        return self.bits


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
    bits=64,
    alter_names=['x86_64'],
    triplet='x86_64-*-*'
)
ARCH_X86 = Arch(
    name='x86',
    bits=32,
    alter_names=['i386', 'i486', 'i686'],
    triplet='i?86-*-*'
)
ARCH_AARCH64 = Arch(
    name='aarch64',
    bits=64,
    alter_names=['arm64'],
    triplet='aarch64-*-*'
)
ARCH_ARMLE = Arch(
    name='armle',
    bits=32,
    alter_names=['armel', 'arm5l'],
    triplet='armv?l-*-*'
)
ARCH_ARMBE = Arch(
    name='armbe',
    endian='big',
    bits=32,
    alter_names=['armeb', 'arm5b'],
    triplet='armv?b-*-*'
)
ARCH_MIPSLE = Arch(
    name='mipsle',
    bits=32,
    alter_names=['mipsel'],
    triplet='mipsel-*-*'
)
ARCH_MIPSBE = Arch(
    name='mipsbe',
    endian='little',
    bits=32,
    alter_names=['mipseb', 'mips'],
    triplet='mips-*-*'
)
ARCH_MIPS64LE = Arch(
    name='mips64le',
    endian='little',
    bits=64,
    alter_names=['mips64el'],
    triplet='mips64el-*-*'
)
ARCH_MIPS64BE = Arch(
    name='mips64be',
    endian='little',
    bits=64,
    alter_names=['mips64', 'mips64eb'],
    triplet='mips64-*-*'
)
ARCH_PPC = Arch(
    name='ppc',
    endian='big',
    bits=32,
    alter_names=['powerpc'],
    triplet='powerpc-*-*'
)
ARCH_PPC64 = Arch(
    name='ppc64',
    endian='little',
    bits=64,
    alter_names=['powerpc64', 'powerpc64le', 'powerpc64el'],
    triplet='powerpc64le-*-*'
)
ARCH_S390X = Arch(
    name='s390x',
    endian='big',
    bits=32,
    alter_names=['zarch', 'ibmz'],
    triplet='s390x-*-*'
)
ARCH_GENERIC = Arch(
    name='generic',
    alter_names=['cmd']
)
