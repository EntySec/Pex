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

    def __add__(self, packet: Any) -> Any:
        """ Add one packet to the current packet.

        :param Any packet: TLV packet to add
        :return Any: new TLV packet
        """

        self.buffer += packet.buffer
        return self.__class__(**vars(self))

    def __sub__(self, packet: Any) -> Any:
        """ Remove one packet from the current packet.

        :param Any packet: TLV packet to remove
        :return Any: new TLV packet
        """

        buffer = bytearray(self.buffer)
        buffer_pos = buffer.find(packet.buffer)

        buffer[buffer_pos:buffer_pos + len(packet.buffer)] = b''
        self.buffer = bytes(buffer)

        return self.__class__(**vars(self))

    def __len__(self) -> int:
        """ Get count of TLV objects.

        :return int: count of TLV objects
        """

        offset = 0
        count = 0

        while offset < len(self.buffer):
            count += 1

            offset += 4
            length = int.from_bytes(
                self.buffer[offset:offset + 4], self.endian)
            offset += 4 + length

        return count

    def __bool__(self) -> bool:
        """ Check if packet is empty or not.

        :return bool: False if empty else True
        """

        return self.__len__() > 0

    def get_raw(self, type: int) -> bytes:
        """ Get raw data from packet.

        :param int type: type
        :return bytes: raw value
        """

        offset = 0

        while offset < len(self.buffer):
            cur_type = int.from_bytes(
                self.buffer[offset:offset + 4], self.endian)
            offset += 4
            cur_length = int.from_bytes(
                self.buffer[offset:offset + 4], self.endian)
            offset += 4
            cur_value = self.buffer[offset:offset + cur_length]
            offset += cur_length

            if cur_type == type:
                self.buffer = bytearray(self.buffer)
                self.buffer[offset - cur_length - 8:offset] = b''
                self.buffer = bytes(self.buffer)

                return cur_value

        return b''

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

    def get_tlv(self, type: int) -> Any:
        """ Get TLV from packet.

        :param int type: type
        :return TLVPacket: TLV packet
        """

        return self.__class__(
            buffer=self.get_raw(type), endian=self.endian)

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

    def add_tlv(self, type: int, value: Any) -> None:
        """ Add TLV packet to packet.

        :param int type: type
        :param Any value: TLV packet
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if value.endian != self.endian:
            raise RuntimeError("Impossible to merge packets with different endians!")

        self.buffer += int.to_bytes(type, 4, self.endian)
        self.buffer += int.to_bytes(len(value.buffer), 4, self.endian)
        self.buffer += value.buffer

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
            elif isinstance(values[value], self.__class__):
                self.add_tlv(value, values[value])
            else:
                self.add_raw(value, values[value])
