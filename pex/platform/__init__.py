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
from pex.type.dataset import DataSet


class Platform(DataSet):
    """ Subclass of pex.platform.types module.

    This subclass of pex.platform.types module is intended for providing
    an implementation of platform set.
    """

    def __init__(self,
                 exec: Optional[str] = None,
                 *args, **kwargs) -> None:
        """ Set platform.

        :param Optional[str] exec: executable format
        (e.g. elf, macho, pe)
        :return None: None
        """

        super().__init__(*args, **kwargs)

        self.exec = exec


OS_ANDROID = Platform(
    name='android',
    exec='elf'
)
OS_MACOS = Platform(
    name='macos',
    alter_names=['osx', 'apple'],
    exec='macho'
)
OS_WINDOWS = Platform(
    name='windows',
    alter_names=['w64'],
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
    alter_names=['iphoneos', 'ios', 'iphone'],
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
