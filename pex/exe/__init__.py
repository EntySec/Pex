"""
MIT License

Copyright (c) 2020-2022 EntySec

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

from .dll import DLL
from .dylib import Dylib

from .pe import PE
from .macho import Macho
from .elf import ELF


class EXE(object):
    """ Main class of pex.exe module.

    This main class of pex.exe module is intended for providing
    some implementations of executable file manipulation methods.
    """

    def __init__(self):
        super().__init__()

        self.dll = DLL()
        self.dylib = Dylib()

        self.pe = PE()
        self.macho = Macho()
        self.elf = ELF()

    def check_executable(self, data: bytes, executable: str = '') -> bool:
        """ Check if data is an executable.

        :param bytes data: data to check
        :param str executable: executable format
        :return bool: True if data is an executable
        """

        exe_map = {
            'dll': self.dll.check_dll,
            'dylib': self.dylib.check_dylib,
            'pe': self.pe.check_pe,
            'macho': self.macho.check_macho,
            'elf': self.elf.check_elf
        }

        if executable in exe_map:
            return exe_map[executable](data)

        for executable in exe_map:
            if exe_map[executable](data):
                return True

        return False

    def executable_replace(self, data: bytes, dst: bytes, src: bytes) -> bytes:
        """ Replace string in executable with content.

        :param bytes data: executable to replace string in
        :param bytes dst: string to replace with content
        :param bytes src: content to replace string with
        :return bytes: processed executable
        """

        if self.check_executable(data):
            content_size = len(src)
            string_size = len(dst)

            string_index = data.index(dst)

            if content_size >= string_size:
                return data[:string_index] + src + data[string_index + content_size:]
            return data[:string_index] + src + data[string_index + string_size:]

        return data.replace(dst, data)
