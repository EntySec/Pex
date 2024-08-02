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

from pex.proto.channel import ChannelTools
from pex.string import String


class Cat(object):
    """ Subclass of pex.post.pull module.

    This subclass of pex.post.pull module is intended for providing
    implementation of cat method of pulling file from sender.
    """

    def __init__(self, config: dict = {}) -> None:
        """ Initialize cat method.

        :param dict config: configuration for method
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.config = {
            'location': None,
        }
        self.config.update(config)

        if not self.config.get('location'):
            raise RuntimeError("Cat: Location is not specified!")

    def pull(self, sender: Callable[..., Any]) -> bytes:
        """ Pull file from sender using cat method.

        :param Callable[..., Any] sender: sender to send commands
        :return bytes: file data
        """

        location = self.config.get('location')

        token = String().random_string(8)
        command = f'cat "{location}" && echo {token}'

        data = sender(command)
        block, _ = ChannelTools().token_extract(data, token.encode())

        return block
