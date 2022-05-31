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

import base64
import random
import re
import string
from itertools import cycle
from typing import Union

from .bit_reader import BitReader
from .lzs_decompress import LZSDecompress
from .ring_list import RingList


class String:
    """ Main class of pex.string module.

    This main class of pex.string module is intended for providing
    implementations of some string features and methods.
    """

    @staticmethod
    def extract_strings(binary_data: str) -> list:
        """ Extract strings from binary data.

        :param str binary_data: data to extract strings from
        :return list: list of extracted strings
        """

        strings = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", binary_data)
        return strings

    @staticmethod
    def xor_string(string: str) -> str:
        """ Perform XOR encryption on a string.

        :param str string: string to perform XOR encryption on
        :return str: XOR encrypted string
        """

        result = ""
        for c in string:
            result += chr(ord(c) ^ len(string))
        return result

    @staticmethod
    def xor_key_string(string: str, key: str) -> str:
        """ Perform key XOR encryption on a string.

        :param str string: string to perform key XOR encryption on
        :param str key: key to encrypt with
        :return str: key XOR encrypted string
        """

        return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(string, cycle(key))])

    @staticmethod
    def xor_key_bytes(buffer: bytes, key: bytes) -> bytes:
        """ Perform key XOR encryption on a bytes buffer.

        :param bytes buffer: buffer to perform key XOR encryption on
        :param bytes key: key to encrypt with
        :return bytes: key XOR encrypted buffer
        """

        return bytes([a ^ b for a, b in zip(buffer, cycle(key))])

    @staticmethod
    def base64_decode(string: str, decode: bool = True) -> Union[str, bytes]:
        """ Decode base64 encoded string.

        :param str string: base64 encoded string to decode
        :param bool decode: decode the result from bytes to str or not
        :return Union[str, bytes]: decoded result in type depending on decode param
        """

        string = base64.b64decode(string)
        return string.decode() if decode else string

    @staticmethod
    def base64_string(string: Union[str, bytes], decode: bool = True) -> Union[str, bytes]:
        """ Encode string with base64.

        :param Union[str, bytes] string: string or bytes to encode with base64
        :param bool decode: decode the result from bytes to str or not
        :return Union[str, bytes]: decoded result in type depending on decode param
        """

        if not isinstance(string, bytes):
            string = string.encode()
        string = base64.b64encode(string)

        return string.decode() if decode else string

    @staticmethod
    def random_string(length: int = 16, alphabet: list = string.ascii_letters + string.digits) -> str:
        """ Generated random string with specified length.

        :param int length: length of a generated string
        :param list alphabet: string alphabet to generate from
        :return str: generated string
        """

        return "".join(random.choice(alphabet) for _ in range(length))

    @staticmethod
    def lzs_decompress(data: bytes, window: RingList = RingList(2048)) -> tuple:
        """ Decompress LZS compressed data.

        :param bytes data: LZS compressed data to decompress
        :param RingList window: RingList list
        :return tuple: decompressed data and RingList
        """

        result, window = LZSDecompress(data, window)
        return result
