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

import collections


class BitReader:
    """ Subclass of pex.string module.

    This subclass of pex.string module is intended for providing
    BitReader Python implementation.
    """

    def __init__(self, data_bytes: bytes) -> None:
        """ BitReader gets a string or an iterable of chars (also mmap)
        representing bytes (ord) and permits to extract bits one by one
        like a stream.

        :param bytes data_bytes: bytes to represent
        :return None: None
        """

        self._bits = collections.deque()

        for byte in data_bytes:
            for n in range(8):
                self._bits.append(bool((byte >> (7 - n)) & 1))

    def getBit(self) -> int:
        """ Get represented bit.

        :return int: represented bit
        """

        return self._bits.popleft()

    def getBits(self, num: int) -> int:
        """ Get represented bits depending on given number.

        :param int num: number
        :return int: represented bit
        """

        res = 0
        for i in range(num):
            res += self.getBit() << num - 1 - i
        return res

    def getByte(self) -> int:
        """ Get represented byte.

        :return int: represented byte
        """

        return self.getBits(8)

    def __len__(self) -> int:
        """ Get lenght of represented bits.

        :return int: length of represented bits
        """

        return len(self._bits)
