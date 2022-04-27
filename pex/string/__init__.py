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

import base64
import random
import re
import string

from itertools import cycle

from .bit_reader import BitReader
from .ring_list import RingList
from .lzs_decompress import LZSDecompress


class String:
    @staticmethod
    def extract_strings(binary_data):
        strings = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", binary_data)
        return strings

    @staticmethod
    def xor_string(string):
        result = ""
        for c in string:
            result += chr(ord(c) ^ len(string))
        return result

    @staticmethod
    def xor_key_string(string, key):
        return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(string, cycle(key))])

    @staticmethod
    def xor_key_bytes(buffer, key):
        return bytes([a ^ b for a, b in zip(buffer, cycle(key))])

    @staticmethod
    def base64_decode(string, decode=True):
        string = base64.b64decode(string)
        return string.decode() if decode else string

    @staticmethod
    def base64_string(string, encoded=False):
        if not encoded:
            string = string.encode()
        string = base64.b64encode(string)
        return string.decode()

    @staticmethod
    def random_string(length=16, alphabet=string.ascii_letters + string.digits):
        return "".join(random.choice(alphabet) for _ in range(length))

    @staticmethod
    def lzs_decompress(data, window=RingList(2048)):
        result, window = LZSDecompress(data, window)
        return result
