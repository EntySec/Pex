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

import os


class Dylib:
    """ Subclass of pex.exe module.

    This subclass of pex.exe module is intended for providing
    an implementation of MacOS dynamic library generator.
    """

    dylib_magic = [
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe"
    ]

    dylib_headers = {
        'x64': f'{os.path.dirname(os.path.dirname(__file__))}/exe/templates/dylib/dylib_x64.dylib',
        'aarch64': f'{os.path.dirname(os.path.dirname(__file__))}/exe/templates/dylib/dylib_aarch64.dylib',
    }

    def pack_dylib(self, arch: str, data: bytes) -> bytes:
        """ Pack data to a MacOS dynamic library.

        :param str arch: architecture to pack for
        :param bytes data: data to pack
        :return bytes: packed MacOS dynamic library
        :raises RuntimeError: with trailing error message
        """

        if data[:4] not in self.dylib_magic:
            if arch in self.dylib_headers:
                if os.path.exists(self.dylib_headers[arch]):
                    data_size = len(data)

                    pointer = b'payload:'.upper()
                    pointer_size = len(pointer)

                    with open(self.dylib_headers[arch], 'rb') as f:
                        dylib = f.read()
                        pointer_index = dylib.index(pointer)

                        if data_size >= pointer_size:
                            return dylib[:pointer_index] + data + dylib[pointer_index + data_size:]
                        return dylib[:pointer_index] + data + dylib[pointer_index + pointer_size:]
                else:
                    raise RuntimeError("Dylib header corrupted!")

            raise RuntimeError("Failed to find compatible dylib header!")
        return data
