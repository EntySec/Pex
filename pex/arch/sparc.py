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

import struct


class Sparc:
    """ Subclass of pex.arch module.

    This subclass of pex.arch module is intended in providing
    implementations of some sparc architecture features.
    """

    registers = {
        'g0': 0, 'g1': 1, 'g2': 2, 'g3': 3,
        'g4': 4, 'g5': 5, 'g6': 6, 'g7': 7,
        'o0': 8, 'o1': 9, 'o2': 10, 'o3': 11,
        'o4': 12, 'o5': 13, 'o6': 14, 'o7': 15,
        'l0': 16, 'l1': 17, 'l2': 18, 'l3': 19,
        'l4': 20, 'l5': 21, 'l6': 22, 'l7': 23,
        'i0': 24, 'i1': 25, 'i2': 26, 'i3': 27,
        'i4': 28, 'i5': 29, 'i6': 30, 'i7': 31,
        'sp': 14, 'fp': 30
    }

    def sethi(self, const: int, dest: str) -> bytes:
        """ Pack sethi sparc assembler instruction.

        :param int const: constant, can be an address
        :param str dest: destination register name
        :return bytes: packed sethi sparc assembler instruction
        """

        return struct.pack('>i',
                           (self.registers[dest] << 25) |
                           (4 << 22) |
                           (const >> 10)
                          )

    def ori(self, src: str, const: int, dest: str) -> bytes:
        """ Pack ori sparc assembler instruction.
        
        :param str src: source register name
        :param int const: constant, can be an address
        :param str dest: destination register name
        :return bytes: packed ori sparc assembler instruction
        """

        return struct.pack('>i',
                           (2 << 30) |
                           (self.registers[dest] << 25) |
                           (2 << 19) |
                           (self.registers[src] << 14) |
                           (1 << 13) |
                           (const & 0x1fff)
                          )

    def set(self, const: int, dest: str) -> bytes:
        """ Pack sparc assembler instruction sethi or ori depending on const size.

        :param int const: constant, can be an address
        :param str dest: destination register name
        :return bytes: packed sethi or ori sparc assembler instruction
        """

        if const <= 4096 and const >= 0:
            return self.ori('g0', const, dest)
        elif const & 0x3ff != 0:
            return self.set_dword(const, dest)
        else:
            return self.sethi(const, dest)

    def set_dword(self, const: int, dest: str) -> bytes:
        """ Pack sparc assembler instruction sethi and ori with const as double word.

        :param int const: constant, can be an address
        :param str dest: destination register name
        :return bytes: packed sethi and ori sparc assembler instruction
        """

        return self.sethi(const, dest) + self.ori(dest, const & 0x3ff, dest)
