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

from pex.assembler import Assembler


class X64:
    """ Subclass of pex.craft module.

    This subclass of pex.craft module is intended in providing
    implementations of some x64 CPU features and models.
    """

    assembler = Assembler()

    def assemble(self, code: str) -> bytes:
        """ Assemble code for x64 architecture.

        :param str code: code to assemble
        :return bytes: assembled code for x64 architecture
        """

        return self.assembler.assemble('x64', code)

    def popad(self) -> bytes:
        """ Pack popad x64 assembler model.

        :return bytes: packed popad x64 assembler model
        """

        return self.assemble(
            """
            start:
                pop rdi
                pop rsi
                pop rbp
                pop rbx
                pop rbx
                pop rdx
                pop rcx
                pop rax
            """
        )

    def crash(self) -> bytes:
        """ Pack crash x64 assembler model.

        :return bytes: packed crash x64 assembler model
        """

        return self.popad() + self.assemble(
            """
            xor rsp, rsp
            jmp rsp
            """
        )
