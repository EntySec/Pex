"""
MIT License

Copyright (c) 2020-2023 EntySec

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

from typing import Union, Any


class TLVPacket(object):
    """ Subclass of pex.proto.tlv module.

    This subclass of pex.proto.tlv module is intended for providing
    an implementation of TLV protocol stack.
    """

    def __init__(self, buffer: bytes = b'', endian: str = 'little') -> None:
        """ Initialize TLV packet.

        :param bytes buffer: raw packet
        :param str endian: byte order of raw packet
        :return None: None
        """

        super().__init__()

        self.endian = endian
        self.buffer = buffer

    def __add__(self, packet: Any) -> self:
        """ Add one packet to the current packet.

        :param Any packet: TLV packet to add
        :return Any: new TLV packet
        """

        return self.__class__(self.buffer + packet.buffer)

    def get_raw(self, type: int) -> bytes:
        """ Get raw data from packet.

        :param int type: type
        :return bytes: raw value
        """

        offset = 0
        data = b''
        buffer = bytearray(self.buffer)

        while offset < len(buffer):
            cur_type = int.from_bytes(
                buffer[offset:offset + 4], self.endian)
            offset += 4
            cur_length = int.from_bytes(
                buffer[offset:offset + 4], self.endian)
            offset += 4
            cur_value = buffer[offset:offset + cur_length]
            offset += cur_length

            if cur_type == type:
                data = cur_value
                del buffer[offset - cur_length - 8:offset]
                break

        self.buffer = bytes(buffer)
        return data

    def get_string(self, type: int) -> str:
        """ Get string from packet.

        :param int type: type
        :return str: string
        """

        return self.get_raw(type).decode()

    def get_int(self, type: int) -> Union[int, None]:
        """ Get integer from packet.

        :param int type: type
        :return Union[int, None]: integer
        """

        data = self.get_raw(type)

        if data:
            return int.from_bytes(data, self.endian)

    def add_raw(self, type: int, value: bytes) -> None:
        """ Add raw data to packet.

        :param int type: type
        :param bytes value: value
        :return None: None
        """

        self.buffer += int.to_bytes(type, 4, self.endian)
        self.buffer += int.to_bytes(len(value), 4, self.endian)
        self.buffer += value

    def add_string(self, type: int, value: str) -> None:
        """ Add string to packet.

        :param int type: type
        :param str value: value
        :return None: None
        """

        self.buffer += int.to_bytes(type, 4, self.endian)
        self.buffer += int.to_bytes(len(value), 4, self.endian)
        self.buffer += value.encode()

    def add_int(self, type: int, value: int) -> None:
        """ Add integer to packet.

        :param int type: type
        :param int value: value
        :return None: None
        """

        self.buffer += int.to_bytes(type, 4, self.endian)
        self.buffer += int.to_bytes(4, 4, self.endian)
        self.buffer += int.to_bytes(value, 4, self.endian)

    def add_from_dict(self, values: dict) -> None:
        """ Add packets from dictionary.

        :param dict values: type as key, value as item
        :return None: None
        """

        for value in values:
            if isinstance(values[value], str):
                self.add_string(value, value)
            elif isinstance(values[value], int):
                self.add_int(value, values[value])
            else:
                self.add_raw(value, values[value])
