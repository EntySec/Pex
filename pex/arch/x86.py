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


class X86:
    EAX = AL = AX = ES = 0
    ECX = CL = CX = CS = 1
    EDX = DL = DX = SS = 2
    EBX = BL = BX = DS = 3
    ESP = AH = SP = FS = 4
    EBP = CH = BP = GS = 5
    ESI = DH = SI = 6
    EDI = BH = DI = 7

    REG_NAMES32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
    REG_NAMES16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']
    REG_NAMES8L = ['al', 'cl', 'dl', 'bl', None, None, None, None]

    @staticmethod
    def get_reg_num(reg):
        if reg in self.REG_NAMES32:
            reg = self.REG_NAMES32.index(reg)

            if reg <= 7 or reg >= 0:
                return reg
        raise RuntimeError(f"Invalid register {reg}!")

    def jmp_reg(self, dest):
        return b"\xff" + struct.pack('B', 224 + self.get_reg_num(dest))

    @staticmethod
    def pack_dword(num):
        return struct.pack('i', num)

    @staticmethod
    def pack_word(num):
        return struct.pack('h', num)

    def pack_lsb(self, num):
        return self.pack_dword(num)[0]

    @staticmethod
    def unpack_dword(dword):
        res, _ = struct.unpack('i', dword)
        return res

    @staticmethod
    def unpack_word(word):
        res, _ = struct.unpack('h', word)
        return res

    @staticmethod
    def push_byte(byte):
        if byte < 128 and byte >= -128:
            return b"\x6a" + bytes([byte & 0xff])
        raise RuntimeError("Only signed byte values allowed!")

    def mov_byte(self, byte, dest):
        return bytes([0xb0 | self.get_reg_num(dest)]) + bytes([byte])

    def mov_word(self, num, dest):
        if num < 0 or num > 0xffff:
            raise RuntimeError("Only unsigned word values allowed!")
        return b"\x66" + bytes([0xb8 | self.get_reg_num(dest)]) + self.pack_word(num)

    def mov_dword(self, num, dest):
        return bytes([0xb8 | self.get_reg_num(dest)]) + self.pack_dword(num)

    def push_dword(self, num):
        return b"\x68" + self.pack_dword(num)

    def push_word(self, num):
        return b"\x66\x68" + self.pack_word(num)

    def pop_dword(self, dest):
        return bytes([0x58 | self.get_reg_num(dest)])

    def dword_adjust(self, dword, num=0):
        return self.pack_dword(self.unpack_dword(dword) + num)

    def word_adjust(self, word, num=0):
        return self.pack_word(self.unpack_word(word) + num)

    def loop(self, offset):
        return b"\xe2" + self.pack_lsb(self.rel_number(offset, -2))

    def jmp(self, addr):
        return b"\xe9" + self.pack_dword(self.rel_number(addr))

    def jmp_short(self, addr):
        return b"\xeb" + self.pack_lsb(self.rel_number(addr, -2))

    def call(self, addr):
        return b"\xe8" + self.pack_dword(self.rel_number(addr, -5))

    @staticmethod
    def rel_number(num, delta=0):
        s = str(num)

        if s[0:2] == '$+':
            num = int(s[2:])
        elif s[0:2] == '$-':
            num = -1 * int(s[2:])
        elif s[0:2] == '0x':
            num = int(s, 16)
        else:
            delta = 0

        return num + delta

    def copy_to_stack(length):
        length = (length + 3) & ~0x3

        return (
            b"\xeb\x0f" +
            self.push_dword(length) +
            b"\x59"
            b"\x5e"
            b"\x29\xcc"
            b"\x89\xe7"
            b"\xf3\xa4"
            b"\xff\xe4"
            b"\xe8\xec\xff\xff\xff"
        )

    def searcher(self, tag):
        return (
            b"\xbe" + self.dword_adjust(tag, -1) +
            b"\x46"
            b"\x47"
            b"\x39\x37"
            b"\x75\xfb"
            b"\x46"
            b"\x4f"
            b"\x39\x77\xfc"
            b"\x75\xfa" +
            self.jmp_reg('edi')
        )

    def encode_effective(self, shift, reg):
        return bytes[0xc0 | (shift << 3) | self.get_reg_num(reg)]

    def encode_modrm(self, src, dest):
        return bytes([0xc0 | self.get_reg_num(src) | self.get_reg_num(dest) << 3])

    @staticmethod
    def fpu_instructions():
        fpus = []

        [fpus.append(b"\xd9" + bytes([i])) for i in range(0xe8, 0xef)]
        [fpus.append(b"\xd9" + bytes([i])) for i in range(0xc0, 0xd0)]
        [fpus.append(b"\xda" + bytes([i])) for i in range(0xc0, 0xe0)]
        [fpus.append(b"\xdb" + bytes([i])) for i in range(0xc0, 0xe0)]
        [fpus.append(b"\xdd" + bytes([i])) for i in range(0xc0, 0xc8)]

        fpus.append(b"\xd9\xd0")
        fpus.append(b"\xd9\xe1")
        fpus.append(b"\xd9\xf6")
        fpus.append(b"\xd9\xf7")
        fpus.append(b"\xd9\xe5")

        return fpus
