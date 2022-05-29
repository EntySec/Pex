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
    """ Subclass for pex.arch base class.

    This subclass of pex.arch module is intended in providing
    implementations of some x86 architecture features.
    """

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

    def get_reg_num(self, reg: str) -> int:
        """ Get register number from a register name.

        :param str reg: register name
        :return int: register number
        """

        if reg in self.REG_NAMES32:
            reg = self.REG_NAMES32.index(reg)

            if reg <= 7 or reg >= 0:
                return reg
        raise RuntimeError(f"Invalid register {reg}!")

    def jmp_reg(self, dest: str) -> bytes:
        """ Pack jmp x86 assembler instruction.

        :param str dest: destination register name
        :return bytes: packed jmp x86 assembler instruction
        """

        return b"\xff" + struct.pack('B', 224 + self.get_reg_num(dest))

    @staticmethod
    def pack_dword(num: int) -> bytes:
        """ Pack integer as double word.

        :param int num: integer to pack
        :return bytes: packed dword
        """

        return struct.pack('i', num)

    @staticmethod
    def pack_word(num: int) -> bytes:
        """ Pack integer as word.

        :param int num: integer to pack
        :return bytes: packed word
        """

        return struct.pack('h', num)

    def pack_lsb(self, num: int) -> bytes:
        """ Pack integer as least significant bit.

        :param int num: integer to pack
        :return bytes: packed lsb
        """

        return self.pack_dword(num)[0]

    @staticmethod
    def unpack_dword(dword: bytes) -> int:
        """ Unpack double word as integer.

        :param bytes dword: double word to unpack
        :return int: unpacked integer
        """

        res, _ = struct.unpack('i', dword)
        return res

    @staticmethod
    def unpack_word(word: bytes) -> int:
        """ Unpack word as integer.

        :param bytes word: word to unpack
        :return int: unpacked integer
        """

        res, _ = struct.unpack('h', word)
        return res

    @staticmethod
    def push_byte(byte: int) -> bytes:
        """ Pack push byte x86 assembler instruction.

        :param int byte: integer to pack as byte and push
        :return bytes: packed push byte x86 assembler instruction
        """

        if byte < 128 and byte >= -128:
            return b"\x6a" + bytes([byte & 0xff])
        raise RuntimeError("Only signed byte values allowed!")

    def mov_byte(self, byte: int, dest: str) -> bytes:
        """ Pack mov byte x86 assembler instruction.

        :param int byte: int to pack as byte and mov
        :param str dest: destination register name
        :return bytes: packed mov byte x86 assembler instruction
        """

        return bytes([0xb0 | self.get_reg_num(dest)]) + bytes([byte])

    def mov_word(self, num: int, dest: str) -> bytes:
        """ Pack mov word x86 assembler instruction.

        :param int num: integer to pack as word and mov
        :param str dest: destination register name
        :return bytes: packed mov word x86 assembler instruction
        """

        if num < 0 or num > 0xffff:
            raise RuntimeError("Only unsigned word values allowed!")
        return b"\x66" + bytes([0xb8 | self.get_reg_num(dest)]) + self.pack_word(num)

    def mov_dword(self, num: int, dest: str) -> bytes:
        """ Pack mov dword x86 assembler instruction.

        :param int num: integer to pack as dword and mov
        :param str dest: destination register name
        :return bytes: packed mov dword x86 assembler instruction
        """

        return bytes([0xb8 | self.get_reg_num(dest)]) + self.pack_dword(num)

    def push_dword(self, num: int) -> bytes:
        """ Pack push dword x86 assembler instruction.

        :param int byte: integer to pack as dword and push
        :return bytes: packed push dword x86 assembler instruction
        """

        return b"\x68" + self.pack_dword(num)

    def push_word(self, num: int) -> bytes:
        """ Pack push word x86 assembler instruction.

        :param int byte: integer to pack as word and push
        :return bytes: packed push word x86 assembler instruction
        """

        return b"\x66\x68" + self.pack_word(num)

    def pop_dword(self, dest: str) -> bytes:
        """ Pack pop dword x86 assembler instruction.

        :param str dest: destination register name
        :return bytes: packed pop dword x86 assembler instruction
        """

        return bytes([0x58 | self.get_reg_num(dest)])

    def dword_adjust(self, dword: bytes, num: int = 0) -> bytes:
        """ Adjust an integer to a double word.

        :param bytes dword: double word to adjust to
        :param int num: integer to adjust
        :return bytes: dword with adjusted integer
        """

        return self.pack_dword(self.unpack_dword(dword) + num)

    def word_adjust(self, word: bytes, num: int = 0) -> bytes:
        """ Adjust an integer to a word.

        :param bytes dword: word to adjust to
        :param int num: integer to adjust
        :return bytes: word with adjusted integer
        """

        return self.pack_word(self.unpack_word(word) + num)

    def loop(self, offset: int) -> bytes:
        """ Pack loop x86 assembler instruction.

        :param int offset: loop x86 assembler instruction offset
        :return bytes: packed loop x86 assembly instruction
        """

        return b"\xe2" + self.pack_lsb(self.rel_number(offset, -2))

    def jmp(self, addr: int) -> bytes:
        """ Pack jmp x86 assembler instruction.

        :param int addr: address to jump to
        :return bytes: packed jmp x86 assembler instruction
        """

        return b"\xe9" + self.pack_dword(self.rel_number(addr))

    def jmp_short(self, addr: int) -> bytes:
        """ Pack jmp short x86 assembler instruction.

        :param int addr: address to jump to
        :return bytes: packed jmp short x86 assembler instruction
        """

        return b"\xeb" + self.pack_lsb(self.rel_number(addr, -2))

    def call(self, addr: int) -> bytes:
        """ Pack call x86 assembler instruction.

        :param int addr: address to call
        :return bytes: packed call x86 assembler instruction
        """

        return b"\xe8" + self.pack_dword(self.rel_number(addr, -5))

    @staticmethod
    def rel_number(num: int, delta: int = 0) -> int:
        """ Get a number offset to the supplied string.

        :param int num: number
        :param int delta: delta to add to a result
        :return int: offset
        """

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

    def copy_to_stack(length: int) -> bytes:
        """ Generate a buffer that will copy memory immediately following
        the stub that is generated to be copied to the stack.

        :param int length: length of a stub
        :return bytes: buffer that will copy memory immediately following
        the stub that us generated to be copied to the stack
        """

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

    def searcher(self, tag: bytes) -> bytes:
        """ Generate a tag-based search routine.

        :param bytes tag: tag to search for
        :return bytes: tag-based search routine
        """
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

    def encode_effective(self, shift: int, reg: str) -> bytes:
        """ Generate encoded effective value for a register.

        :param int shift: effective encoding shift
        :param str reg: register name
        :return bytes: encoded effective value
        """

        return bytes[0xc0 | (shift << 3) | self.get_reg_num(reg)]

    def encode_modrm(self, src: str, dest: str) -> bytes:
        """ Generate mod r/m characted for a source and destination registers.

        :param str src: source register name
        :param str dest: destination register name
        :return bytes: mod r/m character
        """

        return bytes([0xc0 | self.get_reg_num(src) | self.get_reg_num(dest) << 3])

    @staticmethod
    def fpu_instructions() -> list:
        """ Get all floating-point unit x86 assembler instructions.

        :return list: list of FPU instructions as bytes
        """

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
