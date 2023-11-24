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

import os
import lief

from typing import Union, Any

from pex.arch.types import *


class Macho(object):
    """ Subclass of pex.exe module.

    This subclass of pex.exe module is intended for providing
    an implementation of macOS macho generator.
    """

    def __init__(self) -> None:
        super().__init__()

        self.macho_magic = [
            b"\xca\xfe\xba\xbe",
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe"
        ]

        self.macho_headers = {
            ARCH_X64: f'{os.path.dirname(os.path.dirname(__file__))}/exe/templates/macho/macho_x64.macho'
        }

    @staticmethod
    def flatten_macho(data: bytes) -> Any:
        """ Flatten MachO.

        :param bytes data: data to flatten
        :return Any: flattened MachO
        """

        macho = lief.MachO.parse(data)
        min_addr = -1
        max_addr = 0

        for segment in macho.segments:
            if segment.name == '__PAGEZERO':
                if min_addr == -1 or min_addr > segment.virtual_address:
                    min_addr = segment.virtual_address

                if max_addr < segment.virtual_address + segment.virtual_size:
                    max_addr = segment.virtual_address + segment.virtual_size

        flat = b'\x00' * (max_addr - min_addr)

        for segment in macho.segments:
            for section in segment.sections:
                flat_addr = section.virtual_address
                flat_data = data[section.offset:section.size]

                if flat_data:
                    flat[flat_addr:len(flat_data)] = flat_data

        return flat

    def check_macho(self, data: bytes) -> bool:
        """ Check if data is a macOS macho.

        :param bytes data: data to check
        :return bool: True if data is a macOS macho
        """

        return data[:4] in self.macho_magic

    def pack_macho(self, arch: Union[Arch, str], data: bytes) -> bytes:
        """ Pack data to a macOS macho.

        :param Union[Arch, str] arch: architecture to pack for
        :param bytes data: data to pack
        :return bytes: packed macOS macho
        :raises RuntimeError: with trailing error message
        """

        if not self.check_macho(data):
            for header_arch in self.macho_headers:
                if arch != header_arch:
                    continue

                if os.path.exists(self.macho_headers[header_arch]):
                    data_size = len(data)

                    pointer = b'payload:'.upper()
                    pointer_size = len(pointer)

                    with open(self.macho_headers[header_arch], 'rb') as f:
                        macho = f.read()
                        pointer_index = macho.index(pointer)

                        if data_size >= pointer_size:
                            return macho[:pointer_index] + data + macho[pointer_index + data_size:]
                        return macho[:pointer_index] + data + macho[pointer_index + pointer_size:]
                else:
                    raise RuntimeError("Macho header corrupted!")

            raise RuntimeError("Failed to find compatible macho header!")
        return data
