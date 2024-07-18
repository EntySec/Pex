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

import collections

from typing import Any


class RingList(object):
    """ Subclass of pex.string module.

    This subclass of pex.string module is intended for providing
    RingList Python implementation.
    """

    def __init__(self, length: int) -> None:
        """ RingList makes sure that when the list is full,
        for every item appended the older is removed.

        :param int length: length of a list
        :return None: None
        """

        self.__data__ = collections.deque()
        self.__full__ = False
        self.__max__ = length

    def append(self, x: Any) -> None:
        """ Append an item to the list.

        :param Any x: item to append
        :return None: None
        """

        if self.__full__:
            self.__data__.popleft()
        self.__data__.append(x)

        if self.size() == self.__max__:
            self.__full__ = True

    def get(self) -> collections.deque:
        """ Get the list.

        :return collections.deque: list
        """

        return self.__data__

    def size(self) -> int:
        """ Get the size of the list.

        :return int: size of the list
        """

        return len(self.__data__)

    def maxsize(self) -> int:
        """ Get the max size of the list.

        :return int: max size of the list
        """

        return self.__max__

    def __getitem__(self, n: int) -> Any:
        """ Get an item from list by its index.

        :param int n: item index
        :return Any: an item
        """

        if n >= self.size():
            return None
        return self.__data__[n]
