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

from collections import OrderedDict
from typing import Callable

from pex.type import Type
from .cat import Cat
from .dd import DD


class Pull(object):
    """ Main class of pex.post.pull module.

    This main class of pex.post.pull module is intended for providing
    implementations of some functions for pulling files from sender.
    """

    def __init__(self) -> None:
        super().__init__()

        self.type_tools = Type()

        self.pull_methods = OrderedDict({
            'cat': [
                self.type_tools.platforms['unix'],
                Cat()
            ],
            'dd': [
                self.type_tools.platforms['unix'],
                DD()
            ]
        })

    def pull(self, platform: str, sender: Callable, location: str,
             args: list = [], method: str = '') -> bytes:
        """ Pull file from sender.

        :param str platform: sender platform
        :param Callable sender: sender to pull file from
        :param str location: location of file to pull
        :param list args: extra sender arguments
        :param str method: pull method (see self.pull_methods)
        :return bytes: file data
        :raises RuntimeError: with trailing error message
        """

        if method in self.pull_methods or not method:
            if not method:
                for pull_method in self.pull_methods:
                    if platform in self.pull_methods[pull_method][0]:
                        method = pull_method

                if not method:
                    raise RuntimeError(f"No supported post methods found for {platform} platform!")
            else:
                if platform not in self.pull_methods[method][0]:
                    raise RuntimeError(f"Post method {method} is unsupported for {platform} platform!")

            return self.pull_methods[method][1].pull(
                sender=sender,
                location=location,
                args=args
            )
        raise RuntimeError(f"Post method {method} is unsupported!")
