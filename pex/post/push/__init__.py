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

from collections import OrderedDict
from typing import Optional, Union

from pex.platform.types import *

from pex.post.method import Method, select_method
from pex.post.push.bash_echo import BashEcho
from pex.post.push.certutil import Certutil
from pex.post.push.echo import Echo
from pex.post.push.printf import Printf
from pex.post.push.wget import Wget
from pex.post.push.curl import Curl


class Push(object):
    """ Main class of pex.post.push module.

    This main class of pex.post.push module is intended for providing
    implementations of some functions for pushing files to sender.
    """

    def __init__(self) -> None:
        super().__init__()

        self.methods = [
            Method(name='printf', platform=OS_UNIX, handler=Printf(), uri=False),
            Method(name='echo', platform=OS_UNIX, handler=Echo(), uri=False),
            Method(name='bash_echo', platform=OS_UNIX, handler=BashEcho(), uri=False),
            Method(name='certutil', platform=OS_WINDOWS, handler=Certutil(), uri=False),
            Method(name='wget', platform=OS_UNIX, handler=Wget(), uri=True),
            Method(name='curl', platform=OS_UNIX, handler=Curl(), uri=True)
        ]

    def push(self, platform: Union[Platform, str], location: str, method: Optional[str] = None, *args, **kwargs) -> str:
        """ Push file to sender.

        :param Union[Platform, str] platform: sender platform
        :param str location: location of file to push data to
        :param Optional[str] method: push method (see self.push_methods)
        :return str: location of pushed file
        :raises RuntimeError: with trailing error message
        """

        method = select_method(
            methods=self.methods,
            platform=platform,
            method=method
        )

        if method:
            method.handler.push(
                location=location, *args, **kwargs)

            return location

        raise RuntimeError(f"No supported push method found!")
