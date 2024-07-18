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


class Wget(PostTools):
    """ Subclass of pex.post.push module.

    This subclass of pex.post.push module is intended for providing
    implementation of wget method of pushing file to sender.
    """

    def push(self, sender: Callable[..., Any], uri: str, location: str,
             *args, **kwargs) -> None:
        """ Push file to sender using wget method.

        :param Callable[..., Any] sender: sender to push file to
        :param str uri: URI to push file from
        :param str location: location of file to push data to
        :return None: None
        """

        command = "wget -qO {} --no-check-certificate {}"

        self.post_payload(sender, command.format(location, uri))
