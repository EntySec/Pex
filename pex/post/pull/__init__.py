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

from collections import OrderedDict
from typing import Optional, Union

from pex.platform.types import *

from pex.post.method import Method, select_method
from pex.post.pull.cat import Cat
from pex.post.pull.dd import DD


class Pull(object):
    """ Main class of pex.post.pull module.

    This main class of pex.post.pull module is intended for providing
    implementations of some functions for pulling files from sender.
    """

    def __init__(self) -> None:
        super().__init__()

        self.methods = [
            Method(name='cat', platform=OS_UNIX, handler=Cat()),
            Method(name='dd', platform=OS_UNIX, handler=DD())
        ]

    def pull(self, platform: Union[Platform, str], method: Optional[str] = None, *args, **kwargs) -> bytes:
        """ Pull file from sender.

        :param Union[Platform, str] platform: sender platform
        :param Optional[str] method: pull method (see self.pull_methods)
        :return bytes: file data
        :raises RuntimeError: with trailing error message
        """

        method = select_method(
            methods=self.methods,
            platform=platform,
            method=method
        )

        if method:
            return method.handler.pull(*args, **kwargs)

        raise RuntimeError(f"No supported pull method found!")
