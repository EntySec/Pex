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

import io
import struct

from typing import Union

from elftools.elf.elffile import ELFFile

from pex.arch.types import *


class ELF(object):
    """ Subclass of pex.exe module.

    This subclass of pex.exe module is intended for providing
    an implementation of Linux executable and linkable format generator.
    """

    def __init__(self) -> None:
        super().__init__()

        self.elf_magic = [
            b"\x7f\x45\x4c\x46"
        ]

        self.elf_headers = {
            ARCH_ARMLE: (
                b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
                b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00"
                b"\x00\x80\x00\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
                b"\x00\x10\x00\x00"
            ),
            ARCH_MIPSBE: (
                b"\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\x54\x00\x00\x00\x34"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00"
                b"\x00\x40\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xef\x00\x00\x00\x07"
                b"\x00\x00\x10\x00"
            ),
            ARCH_MIPSLE: (
                b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02\x00\x08\x00\x01\x00\x00\x00\x54\x00\x40\x00\x34\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
                b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00"
                b"\x00\x00\x40\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
                b"\x00\x10\x00\x00"
            ),
            ARCH_X86: (
                b"\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02\x00\x03\x00\x01\x00\x00\x00\x54\x80\x04\x08\x34\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
                b"\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x04\x08"
                b"\x00\x80\x04\x08\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
                b"\x00\x10\x00\x00"
            ),
            ARCH_AARCH64: (
                b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02\x00\xb7\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
                b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                b"\x01\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
                b"\xef\xbe\xad\xde\x00\x00\x00\x00\xef\xbe\xad\xde\x00\x00\x00\x00"
                b"\x00\x10\x00\x00\x00\x00\x00\x00"
            ),
            ARCH_X64: (
                b"\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
                b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x00\x00\x00\x00\x00\x00"
                b"\x01\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00"
                b"\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x42\x42\x42\x42"
                b"\x00\x10\x00\x00\x00\x00\x00\x00"
            )
        }

    def check_elf(self, data: bytes) -> bool:
        """ Check if data is a Linux executable and linkable format.

        :param bytes data: data to check
        :return bool: True if data is a Linux executable and linkable format
        """

        return data[:4] in self.elf_magic

    @staticmethod
    def elf_header(data: bytes) -> dict:
        """ Get ELF file data header.

        :param bytes data: data to parse
        :return dict: header, header names as keys and
            header offsets as items
        """

        elf = ELFFile(io.BytesIO(data))
        return elf.header

    def pack_elf(self, arch: Union[Arch, str], data: bytes) -> bytes:
        """ Pack data to a Linux executable and linkable format.

        :param Union[Arch, str] arch: architecture to pack for
        :param bytes data: data to pack
        :return bytes: packed Linux executable and linkable format
        :raises RuntimeError: with trailing error message
        """

        if not self.check_elf(data):
            for header_arch in self.elf_headers:
                if arch != header_arch:
                    continue

                elf = self.elf_headers[header_arch] + data

                if elf[4] == 1:
                    if str(arch).endswith('be'):
                        p_filesz = struct.pack(">L", len(elf))
                        p_memsz = struct.pack(">L", len(elf) + len(data))
                    else:
                        p_filesz = struct.pack("<L", len(elf))
                        p_memsz = struct.pack("<L", len(elf) + len(data))
                    content = elf[:0x44] + p_filesz + p_memsz + elf[0x4c:]

                elif elf[4] == 2:
                    if str(arch).endswith('be'):
                        p_filesz = struct.pack(">Q", len(elf))
                        p_memsz = struct.pack(">Q", len(elf) + len(data))
                    else:
                        p_filesz = struct.pack("<Q", len(elf))
                        p_memsz = struct.pack("<Q", len(elf) + len(data))
                    content = elf[:0x60] + p_filesz + p_memsz + elf[0x70:]

                else:
                    raise RuntimeError("ELF header corrupted!")
                return content

            raise RuntimeError("Failed to find compatible ELF header!")
        return data
