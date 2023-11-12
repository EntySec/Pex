"""
MIT License

Copyright (c) 2020-2023 EntySec

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


class Platform(object):
    """ Subclass of pex.platform.types module.

    This subclass of pex.platform.types module is intended for providing
    an implementation of platform descriptor.
    """

    def __init__(self,
                 name: str,
                 alter_names: list = [],
                 exec: Optional[str] = None,
                 sub_sets: list = []) -> None:
        """ Set platform.

        :param str name: platform name
        :param list alter_names: platform alternative names if presented
        (e.g. macos - osx, apple_ios - iphoneos, cisco_ios - ios)
        :param Optional[str] exec: executable format
        (e.g. elf, macho, pe)
        :param list sub_sets: sub sets of this platform
        (e.g. unix may have a sub set of linux, since linux is unix)
        :return None: None
        """

        super().__init__()

        self.name = name.lower()
        self.alter_names = alter_names
        self.exec = exec
        self.sub_sets = sub_sets

    def __hash__(self) -> int:
        """ Make this architecture hashable.

        :return int: architecture hash
        """

        return hash(self.name)

    def __add__(self, platform: Any) -> Any:
        """ Add platform to current platform sub sets.

        :param Any platform: platform to add
        :return Any: updated platform
        """

        self.sub_sets.append(platform)
        return self.__class__(**vars(self))

    def __sub__(self, platform: Any) -> Any:
        """ Remove platform from current sub sets.

        :param Any platform: platform to remove
        :return Any: updated platform
        """

        if platform in self.sub_sets:
            self.sub_sets.remove(platform)

        return self.__class__(**vars(self))

    def __str__(self) -> str:
        """ Covert to string.

        :return str: platform name
        """

        return self.name

    def __contains__(self, platform: Any) -> bool:
        """ Check if platform is a sub set of current one.

        :param Any platform: can be platform name of alternative name
        :return bool: True if contains else False
        """

        if isinstance(platform, str):
            if platform.lower() == self:
                return True

            for sub_set in self.sub_sets:
                if platform.lower() == sub_set:
                    return True

        elif isinstance(platform, self.__class__):
            if platform == self:
                return True

            for sub_set in self.sub_sets:
                if platform == sub_set or platform in sub_set:
                    return True

        return False

    def __eq__(self, platform: Any) -> bool:
        """ Check if platform compatible with current one.

        :param Any platform: can be platform name or alternative name
        :return bool: True if compatible else False
        """

        if isinstance(platform, str):
            if platform.lower() == 'generic' or \
                    platform.lower() == self.name \
                    or platform in self.alter_names:
                return True

        elif isinstance(platform, self.__class__):
            if platform.name == 'generic' or \
                    platform.name == self.name or \
                    platform.name in self.alter_names:
                return True

        return False


OS_ANDROID = Platform(
    name='android',
    exec='elf'
)
OS_MACOS = Platform(
    name='macos',
    alter_names=['osx'],
    exec='macho'
)
OS_WINDOWS = Platform(
    name='windows',
    exec='pe'
)
OS_LINUX = Platform(
    name='linux',
    exec='elf'
)
OS_BSD = Platform(
    name='bsd',
    exec='elf'
)
OS_IPHONE = Platform(
    name='apple_ios',
    alter_names=['iphoneos'],
    exec='macho'
)
OS_UNIX = Platform(
    name='unix',
    sub_sets=[
        OS_LINUX,
        OS_MACOS,
        OS_IPHONE
    ]
)
OS_GENERIC = Platform(
    name='generic',
)

EXEC_FORMATS = {
    OS_MACOS.exec: [OS_MACOS, OS_IPHONE],
    OS_LINUX.exec: [OS_LINUX, OS_UNIX, OS_ANDROID, OS_BSD],
    OS_WINDOWS.exec: [OS_WINDOWS]
}
