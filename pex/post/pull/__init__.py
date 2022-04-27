#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from collections import OrderedDict

from pex.type import Type

from .dd import DD
from .cat import Cat


class Pull:
    type_tools = Type()

    pull_methods = OrderedDict({
        'cat': [
            type_tools.platforms['unix'],
            Cat()
        ],
        'dd': [
            type_tools.platforms['unix'],
            DD()
        ]
    })

    def pull(self, platform, sender, location, args=[], method=None):
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
