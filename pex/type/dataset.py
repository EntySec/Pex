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

from typing import Any, Optional


class DataSet(object):
    """ Subclass of pex.type.dataset module.

    This subclass of pex.type.dataset module is intended for providing
    an implementation of data set used to store data in the form of set.
    """

    def __init__(self,
                 name: str,
                 alter_names: list = [],
                 sub_sets: list = []) -> None:
        """ Set data set.

        :param str name: set name
        :param list alter_names: set alternative names if presented
        :param list sub_sets: sub sets of this set
        :return None: None
        """

        super().__init__()

        self.name = name.lower()
        self.alter_names = alter_names
        self.sub_sets = sub_sets

    def __add__(self, value: Any) -> Any:
        """ Add set to current set sub sets.

        :param Any value: value to add
        :return Any: updated set
        """

        self.sub_sets.append(value)
        return self.__class__(**vars(self))

    def __sub__(self, value: Any) -> Any:
        """ Remove set from current sub sets.

        :param Any value: value to remove
        :return Any: updated set
        """

        if value in self.sub_sets:
            self.sub_sets.remove(value)

        return self.__class__(**vars(self))

    def __hash__(self) -> int:
        """ Make this set hashable.

        :return int: set hash
        """

        return hash(self.name)

    def __str__(self) -> str:
        """ Covert to string.

        :return str: set name
        """

        return self.name

    def __contains__(self, value: Any) -> bool:
        """ Check if value is a sub set of current set.

        :param Any value: can be set name of alternative name
        :return bool: True if contains else False
        """

        if isinstance(value, str):
            if value.lower() == self.name:
                return True

            for sub_set in self.sub_sets:
                if value.lower() == sub_set:
                    return True

        elif isinstance(value, self.__class__):
            if value == self:
                return True

            for sub_set in self.sub_sets:
                if value == sub_set or value in sub_set:
                    return True

        return False

    def __eq__(self, value: Any) -> bool:
        """ Check if set compatible with current set.

        :param Any value: can be set name or alternative name
        :return bool: True if compatible else False
        """

        if isinstance(value, str):
            if value.lower() == self.name or \
                    value in self.alter_names:
                return True

        elif isinstance(value, self.__class__):
            if value.name == self.name or \
                    value.name in self.alter_names:
                return True

        return False
