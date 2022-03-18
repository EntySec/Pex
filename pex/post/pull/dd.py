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


class DD:
    @staticmethod
    def pull(sender, location, args=[]):
        result = b""

        dd_stream = "dd if={} of=/dev/stdout bs={} count=1 skip={} 2>/dev/null"
        dd_chunk_size = 1024

        with alive_bar(None, receipt=False, ctrl_c=False, title="Pulling") as bar:
            dd_counter = 0

            while True:
                command = dd_stream.format(
                    location,
                    str(dd_chunk_size),
                    str(dd_counter)
                )
                
                if isinstance(args, dict):
                    data = sender(command, **args)
                else:
                    data = sender(*args, command)
                    
                if data:
                    result += data
                    dd_counter += 1

                    continue
                break

        return result
