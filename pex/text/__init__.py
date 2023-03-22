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


class Text(object):
    """ Main class of pex.text module.

    This main class of pex.text module is intended for providing
    implementations of tools for working with various text data.
    """

    def __init__(self) -> None:
        super().__init__()

    def block_api_hash(self, mod: str, fun: str) -> str:
        """ Calculate the block API hash for the given module/function.

        :param str mod: the name of the module containing the target function
        :param str fun: the name of the function
        :return str: the hash of the mod/fun pair in string format
        """

        unicode_mod = (mod.upper() + "\x00").encode('utf-16le')
        mod_hash = self.ror13_hash(unicode_mod)
        fun_hash = self.ror13_hash((fun + "\x00").encode())

        return "0x{:x}".format((mod_hash + fun_hash) & 0xFFFFFFFF)

    def ror13_hash(self, name: str) -> bytes:
        """ Calculate the ROR13 hash of a given string.

        :param str name: string
        :return bytes: ROR13 hash
        """

        hash_val = 0

        for c in name:
            hash_val = self.ror(hash_val, 13)
            hash_val += ord(c)

        return hash_val

    @staticmethod
    def ror(val: int, cnt: int) -> int:
        """ Rotate value.

        :param int val: value
        :param int cnt: count
        :return int: rotated value
        """

        bits = format(val, '032b')
        bits = list(bits)

        for c in range(cnt):
            bits.insert(0, bits.pop())

        bits = ''.join(bits)
        return int(bits, 2)
