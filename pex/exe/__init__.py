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
from .elf import ELF
from .macho import Macho
from .dylib import Dylib
from .pe import PE


class EXE:
    """ Main class of pex.exe module.

    This main class of pex.exe module is intended for providing
    some implementations of executable file manipulation methods.
    """

    @staticmethod
    def executable_replace(data: bytes, string: str, content: bytes) -> bytes:
        """ Replace string in executable with content.

        :param bytes data: executable to replace string in
        :param str string: string to replace with content
        :param bytes content: content to replace string with
        :return bytes: processed executable
        """

        content_size = len(content)
        string_size = len(string)

        string_index = data.index(string)

        if content_size >= string_size:
            return data[:string_index] + content + data[string_index + content_size:]
        return data[:string_index] + content + data[string_index + string_size:]
