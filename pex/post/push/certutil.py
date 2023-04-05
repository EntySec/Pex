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

from typing import Callable, Any
from alive_progress import alive_bar

from pex.post.tools import PostTools
from pex.string import String


class Certutil(object):
    """ Subclass of pex.post.push module.

    This subclass of pex.post.push module is intended for providing
    implementation of certutil method of pushing file to sender.
    """

    def __init__(self) -> None:
        super().__init__()

        self.post_tools = PostTools()
        self.string_tools = String()

    def push(self, sender: Callable[..., Any], data: bytes, location: str,
             linemax: int = 100, *args, **kwargs) -> None:
        """ Push file to sender using bash echo method.

        :param Callable[..., Any] sender: sender to push file to
        :param bytes data: data to push to file on sender
        :param str location: location of file to push data to
        :param int linemax: max command line size for each chunk
        :return None: None
        """

        decode_stream = "certutil -decode {}.b64 {}.exe & del {}.b64"

        echo_stream = "echo {} >> {}.b64"
        echo_max_length = linemax

        data = self.string_tools.base64_string(data, decode=False)

        size = len(data)
        num_parts = int(size / echo_max_length) + 1

        with alive_bar(num_parts, receipt=False, ctrl_c=False, title="Pushing") as bar:
            for i in range(0, num_parts):
                bar()

                current = i * echo_max_length
                block = data[current:current + echo_max_length]

                if block:
                    command = echo_stream.format(block, location)
                    self.post_tools.post_payload(sender, command, *args, **kwargs)

        command = decode_stream.format(location, location, location)
        self.post_tools.post_payload(sender, command, *args, **kwargs)
