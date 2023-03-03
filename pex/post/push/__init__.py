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

from pex.type import Type
from .bash_echo import BashEcho
from .certutil import Certutil
from .echo import Echo
from .printf import Printf


class Push(object):
    def __init__(self):
        super().__init__()

        self.type_tools = Type()

        self.push_methods = OrderedDict({
            'printf': [
                self.type_tools.platforms['unix'],
                Printf()
            ],
            'echo': [
                self.type_tools.platforms['unix'],
                Echo()
            ],
            'bash_echo': [
                self.type_tools.platforms['unix'],
                BashEcho()
            ],
            'certutil': [
                self.type_tools.platforms['windows'],
                Certutil()
            ]
        })

    def push(self, platform, sender, data, location, args=[], method=None, linemax=100):
        if method in self.push_methods or not method:
            if not method:
                for push_method in self.push_methods:
                    if platform in self.push_methods[push_method][0]:
                        method = push_method

                if not method:
                    raise RuntimeError(f"No supported post methods found for {platform} platform!")
            else:
                if platform not in self.push_methods[method][0]:
                    raise RuntimeError(f"Post method {method} is unsupported for {platform} platform!")

            self.push_methods[method][1].push(
                sender=sender,
                data=data,
                location=location,
                args=args,
                linemax=linemax
            )
            return location
        raise RuntimeError(f"Post method {method} is unsupported!")
