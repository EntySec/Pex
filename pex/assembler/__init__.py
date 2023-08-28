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

from hatasm import HatAsm


class Assembler(object):
    """ Main class of pex.assembler module.

    This main class of pex.assembler module is intended for providing
    an implementation of native assembler.
    """

    def __init__(self) -> None:
        super().__init__()

        self.hatasm = HatAsm()

    def assemble(self, arch: str, code: str, mode: str = '', syntax: str = 'intel') -> bytes:
        """ Assemble code for the specified architecture.

        :param str arch: architecture to assemble for
        :param str code: code to assemble
        :param str mode: special assembler mode
        :param str syntax: special assembler syntax
        :return bytes: assembled code for the specified architecture
        """

        return self.hatasm.assemble(arch, code, mode, syntax)

    def hexdump(self, code: bytes, length: int = 16, sep: str = '.') -> list:
        """ Dump assembled code as hex.

        :param bytes code: assembled code to dump as hex
        :param int length: length of each string
        :param str sep: non-printable chars replacement
        :return list: list of hexdump strings
        """

        return self.hatasm.hexdump(code, length, sep)
