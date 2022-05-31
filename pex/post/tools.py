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


class PostTools:
    """ Subclass of pex.post module.

    This subclass of pex.post module is intended for providing
    implementations of some helpful tools for pex.post.
    """

    @staticmethod
    def bytes_to_octal(bytes_obj: bytes, extra_zero: bool = False) -> str:
        """ Convert bytes to their octal representation.

        :param bytes bytes_obj: bytes to convert
        :param bool extra_zero: add extra_zero to the result
        :return str: octal representation of bytes
        """

        byte_octals = []
        for byte in bytes_obj:
            byte_octal = '\\0' if extra_zero else '\\'
            byte_octal += oct(byte)[2:]

            byte_octals.append(byte_octal)
        return ''.join(byte_octals)

    @staticmethod
    def post_command(sender, command: str, args: dict) -> str:
        """ Post command to sender and recieve the result.

        :param sender: sender function
        :param str command: command to post
        :param dict args: sender function arguments
        :return str: post command result
        """

        return sender(**{
            'command': command,
            **args
        })
