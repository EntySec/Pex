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

from typing import Callable, Any
from alive_progress import alive_bar

from pex.post.tools import PostTools
from pex.proto.channel import ChannelTools
from pex.string import String


class DD(object):
    """ Subclass of pex.post.pull module.

    This subclass of pex.post.pull module is intended for providing
    implementation of dd method of pulling file from sender.
    """

    def __init__(self) -> None:
        super().__init__()

        self.post_tools = PostTools()
        self.string_tools = String()
        self.channel_tools = ChannelTools()

    def pull(self, sender: Callable[..., Any], location: str) -> bytes:
        """ Pull file from sender using dd method.

        :param Callable[..., Any] sender: sender to pull file from
        :param str location: location of file to pull
        :return bytes: file data
        :raises RuntimeError: with trailing error message
        """

        result = b""

        dd_stream = "dd if={} of=/dev/stdout bs={} count=1 skip={} 2>/dev/null && echo {}"
        dd_chunk_size = 1024

        with alive_bar(None, receipt=False, ctrl_c=False, title="Pulling") as bar:
            dd_counter = 0

            while True:
                bar()

                token = self.string_tools.random_string(8)
                command = dd_stream.format(
                    location,
                    str(dd_chunk_size),
                    str(dd_counter),
                    token
                )

                data = self.post_tools.post_payload(sender, command)
                block, _ = self.channel_tools.token_extract(data, token.encode())

                result += block

                if block != data:
                    break

        return result
