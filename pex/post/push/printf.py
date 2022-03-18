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

from alive_progress import alive_bar

from pex.post import PostTools


class Printf(PostTools):
    @staticmethod
    def bytes_to_octal(bytes_obj):
        byte_octals = []
        for byte in bytes_obj:
            byte_octal = '\\' + oct(byte)[2:]
            byte_octals.append(byte_octal)
        return ''.join(byte_octals)

    def push(self, sender, data, location, args=[], linemax=100):
        printf_stream = "printf '{}' >> {}"
        printf_max_length = linemax

        size = len(data)
        num_parts = int(size / printf_max_length) + 1

        with alive_bar(num_parts, receipt=False, ctrl_c=False, title="Pushing") as bar:
            for i in range(0, num_parts):
                bar()

                current = i * printf_max_length
                block = self.bytes_to_octal(data[current:current + printf_max_length])

                if block:
                    command = printf_stream.format(block, location)
                    self.post_command(sender, command, args)
