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

from .bit_reader import BitReader
from .ring_list import RingList

from typing import Tuple


def LZSDecompress(data: bytes, window: RingList = RingList(2048)) -> Tuple[bytes, list]:
    """ Decompress LZS compressed data.

    :param bytes data: LZS compressed data to decompress
    :param RingList window: RingList list
    :return Tuple[bytes, list]: decompressed data and RingList
    """

    reader = BitReader(data)
    result = ''

    while True:
        bit = reader.get_bit()

        if not bit:
            char = reader.get_byte()
            result += chr(char)

            window.append(char)
        else:
            bit = reader.get_bit()

            if bit:
                offset = reader.get_bits(7)

                if offset == 0:
                    break
            else:
                offset = reader.get_bits(11)

            len_field = reader.get_bits(2)

            if len_field < 3:
                length = len_field + 2
            else:
                len_field <<= 2
                len_field += reader.get_bits(2)

                if len_field < 15:
                    length = (len_field & 0x0f) + 5
                else:
                    len_counter = 0
                    len_field = reader.get_bits(4)

                    while len_field == 15:
                        len_field = reader.get_bits(4)
                        len_counter += 1

                    length = 15 * len_counter + 8 + len_field

            for _ in range(length):
                char = window[-offset]
                result += chr(char)

                window.append(char)

    return result, window
