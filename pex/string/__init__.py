"""
MIT License

Copyright (c) 2020-2024 EntySec

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

import re
import stat
import base64
import random
import string
import struct

from itertools import cycle
from typing import Union
from datetime import datetime

from .bit_reader import BitReader
from .lzs_decompress import lzs_decompress
from .ring_list import RingList


class String(object):
    """ Main class of pex.string module.

    This main class of pex.string module is intended for providing
    implementations of some string features and methods.
    """

    @staticmethod
    def bytes_to_octal(bytes_obj: bytes, extra_zero: bool = False) -> str:
        """ Convert bytes to their octal representation.

        :param bytes bytes_obj: bytes to convert
        :param bool extra_zero: add extra_zero to the result
        :return str: octal representation of bytes
        """

        byte_octals = []

        for byte in bytes_obj:
            byte_octal = '\\0' if extra_zero else '\\'
            byte_octal += oct(byte)[2:]

            byte_octals.append(byte_octal)

        return ''.join(byte_octals)

    @staticmethod
    def split_args(args: str) -> list:
        """ Split argv/args list.

        :param str args: argv/args list
        :return list: array of args
        """

        args = re.split(''' (?=(?:[^'"]|'[^']*'|"[^"]*")*$)''', args)
        argv = []

        for arg in args:
            if arg:
                argv.append(arg.strip('"').strip("'"))

        return argv

    @staticmethod
    def size_normalize(size: int, ratio: int = 1024) -> str:
        """ Size to B, KB, MB, GB, TB

        :param int size: size in bytes
        :param int ratio: ratio (divide by it)
        :return str: size with units
        """

        units = ["B", "KB", "MB", "GB", "TB"]
        index = 0

        while size >= ratio and index < len(units) - 1:
            size /= ratio
            index += 1

        return f"{size:.2f} {units[index]}"

    @staticmethod
    def time_normalize(timestamp: int) -> str:
        """ Normalize time format from timestamp.

        :param int timestamp: timestamp
        :return str: formatted time
        """

        return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def mode_symbolic(mode: int) -> str:
        """ Return the symbolic form of file mode.

        :param int mode: mode
        :return str: symbolic form of file mode
        """

        perms = ''

        for _ in range(3):
            perms = ('x' if (mode & 0o1) == 0o1 else '-') + perms
            perms = ('w' if (mode & 0o2) == 0o2 else '-') + perms
            perms = ('r' if (mode & 0o4) == 0o4 else '-') + perms
            mode >>= 3

        return perms

    @staticmethod
    def mode_type(mode: int) -> str:
        """ Get type of file by mode.

        :param int mode: mode
        :return str: type of file
        """

        if stat.S_ISREG(mode):
            return "file"

        if stat.S_ISDIR(mode):
            return "directory"

        if stat.S_ISCHR(mode):
            return "character device"

        if stat.S_ISBLK(mode):
            return "block device"

        if stat.S_ISFIFO(mode):
            return "pipe"

        if stat.S_ISSOCK(mode):
            return "socket"

        if stat.S_ISLNK(mode):
            return "symlink"

        return "???"

    @staticmethod
    def bytes_to_stat(buffer: bytes) -> dict:
        stat_hash = {}
        skeys = ['st_dev',
                 'st_mode',
                 'st_nlink',
                 'st_uid',
                 'st_gid',
                 'st_rdev',
                 'st_ino',
                 'st_size',
                 'st_atime',
                 'st_mtime',
                 'st_ctime']
        svals = struct.unpack("IIIIIIQQQQQ", buffer)

        for i in range(len(skeys)):
            stat_hash[skeys[i]] = svals[i]

        return stat_hash

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

        result, window = lzs_decompress(data, window)
        return result

    @staticmethod
    def hexdump(code: bytes, length: int = 16, sep: str = '.') -> list:
        """ Dump bytes as hex.

        :param bytes code: bytes to dump as hex
        :param int length: length of each string
        :param str sep: non-printable chars replacement
        :return list: list of hexdump strings
        """

        src = code
        filt = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
        lines = []

        for c in range(0, len(src), length):
            chars = src[c: c + length]
            hex_ = ' '.join(['{:02x}'.format(x) for x in chars])

            if len(hex_) > 24:
                hex_ = '{} {}'.format(hex_[:24], hex_[24:])

            printable = ''.join(['{}'.format((x <= 127 and filt[x]) or sep) for x in chars])
            lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))

        return lines
