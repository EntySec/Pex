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

from typing import Callable, Any, Union

from pex.string import String
from pex.type import Type
from .push import Push
from .tools import PostTools


class Post(object):
    """ Main class of pex.post module.

    This main class of pex.post module is intended for providing
    an implementation of post function that sends a data to the target.
    """

    def __init__(self) -> None:
        super().__init__()

        self.push = Push()

        self.post_tools = PostTools()
        self.type_tools = Type()
        self.string_tools = String()

        self.post_methods = self.push.push_methods

    def post(self, payload: Union[bytes, str], sender: Callable[..., Any], platform: str,
             architecture: str, arguments: str = '', method: str = '', location: str = '',
             concat: str = '', background: str = '', linemax: int = 100, *args, **kwargs) -> None:
        """ Post a payload through the sender function.

        :param Union[bytes, str] payload: payload to post
        :param Callable[..., Any] sender: sender function to port through
        :param str platform: target platform
        :param str architecture: target architecture
        :param str arguments: payload arguments
        :param str method: post method to use
        :param str location: path to save payload
        :param str concat: post command concat operator
        :param str background: post command background operator
        :param int linemax: maximum size of a post command
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        platforms = self.type_tools.platforms
        architectures = self.type_tools.architectures

        if method in self.post_methods or not method:
            if not method:
                for post_method in self.post_methods:
                    if platform in self.post_methods[post_method][0]:
                        method = post_method
                        break

                if not method:
                    raise RuntimeError(f"No supported post methods found for {platform} platform!")
            else:
                if platform not in self.post_methods[method][0]:
                    raise RuntimeError(f"Post method {method} is unsupported for {platform} platform!")

            filename = self.string_tools.random_string(8)
            arguments = '' if not arguments else arguments

            if platform in platforms['unix']:
                if not location:
                    location = '/tmp'
                if not concat:
                    concat = ';'
                if not background:
                    background = '&'

                path = location + '/' + filename

                if architecture in architectures['cpu']:
                    command = f"sh -c 'chmod 777 {path} {concat} {path} {arguments} {concat} rm {path}' {background}"

                elif architecture in architectures['generic']:
                    if platform in architectures['generic'][architecture]['platforms']:
                        command = f"{architectures['generic'][architecture]['command']} {path} {arguments} {concat} rm {path}"
                    else:
                        raise RuntimeError(f"Platform {platform} is not supported by {architecture} architecture!")

                else:
                    self.post_tools.post_payload(sender, payload, *args, **kwargs)
                    return

            elif platform in platforms['windows']:
                if not location:
                    location = '%TEMP%'
                if not concat:
                    concat = '&'
                if not background:
                    background = ''

                path = location + '\\' + filename

                if architecture in architectures['cpu']:
                    command = f"{background} {path} {arguments} {concat} del {path}"

                elif architecture in architectures['generic']:
                    if platform in architectures['generic'][architecture]['platforms']:
                        command = f"{background} {architectures['generic'][architecture]['command']} {path} {arguments} {concat} del {path}"
                    else:
                        raise RuntimeError(f"Platform {platform} is not supported by {architecture} architecture!")

                else:
                    self.post_tools.post_payload(sender, payload, *args, **kwargs)
                    return
            else:
                raise RuntimeError(f"Platform {platform} in unsupported!")

            self.post_methods[method][1].push(
                sender=sender,
                data=payload if isinstance(payload, bytes) else payload.encode(),
                location=path,
                linemax=linemax,
                *args, **kwargs
            )

            self.post_tools.post_payload(sender, command, *args, **kwargs)
        else:
            self.post_tools.post_payload(sender, payload, *args, **kwargs)
