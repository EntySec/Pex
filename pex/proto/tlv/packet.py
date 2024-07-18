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

import struct

from typing import Union, Any


class TLVPacket(object):
    """ Subclass of pex.proto.tlv module.

    This subclass of pex.proto.tlv module is intended for providing
    an implementation of TLV protocol stack.
    """

    def __init__(self, buffer: bytes = b'') -> None:
        """ Initialize TLV packet.

        :param bytes buffer: raw packet
        :return None: None
        """

        self.buffer = buffer
        self.values = {}

        self.serialize()

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
            length = self.next_int(offset)

            if length is None:
                break

            offset += 4 + length

        return count

    def __bool__(self) -> bool:
        """ Check if packet is empty or not.

        :return bool: False if empty else True
        """

        return self.__len__() > 0

    def next_int(self, offset: int = 0) -> Union[int, None]:
        """ Get next integer from buffer.

        :param int offset: buffer offset
        :return Union[int, None]: integer if there is integer else None
        """

        value = self.buffer[offset:offset + 4]

        if len(value) == 4:
            return struct.unpack('!I', value)[0]

    def serialize(self) -> None:
        """ Serialize TLV packet.

        :return None: None
        """

        offset = 0

        while offset < len(self.buffer):
            cur_type = self.next_int(offset)
            if cur_type is None:
                break

            offset += 4
            cur_length = self.next_int(offset)
            if cur_length is None:
                break

            offset += 4
            cur_value = self.buffer[offset:offset + cur_length]
            offset += cur_length

            if cur_type not in self.values:
                self.values[cur_type] = cur_value
                continue

            if not isinstance(self.values[cur_type], list):
                self.values[cur_type] = [
                    self.values[cur_type], cur_value]
                continue

            self.values[cur_type].append(cur_value)

    def clean(self) -> None:
        """ Clean TLV packet buffer (e.g. from padding)

        :return None: None
        """

        offset = 0
        buffer = b""

        while offset < len(self.buffer):
            curr_type = self.next_int(offset)
            if curr_type is None:
                break

            offset += 4
            cur_length = self.next_int(offset)
            if cur_length is None:
                break

            offset += 4
            cur_value = self.buffer[offset:offset + cur_length]

            if len(cur_value) != cur_length:
                break

            offset += cur_length
            buffer = self.buffer[:offset]

        self.buffer = buffer

    def get_raw(self, type: int, delete: bool = True) -> bytes:
        """ Get raw data from packet.

        :param int type: type
        :param bool delete: True to delete element else False
        :return Union[bytes, list]: raw value or list of raw values
        """

        if not self.values:
            raise RuntimeError("TLV packet is not serialized!")

        value = self.values.get(type, b'')

        if not value:
            return value

        if not isinstance(value, list):
            if delete:
                del self.values[type]

            return value

        if delete:
            return value.pop(0)

        return value[0]

    def get_string(self, *args, **kwargs) -> str:
        """ Get string from packet.

        :return str: string
        """

        return self.get_raw(*args, **kwargs).decode()

    def get_short(self, *args, **kwargs) -> Union[int, None]:
        """ Get short integer from packet.

        :return Union[int, None]: short integer
        """

        data = self.get_raw(*args, **kwargs)

        if data and len(data) == 2:
            return struct.unpack('!H', data)[0]

    def get_int(self, *args, **kwargs) -> Union[int, None]:
        """ Get integer from packet.

        :return Union[int, None]: integer
        """

        data = self.get_raw(*args, **kwargs)

        if data and len(data) == 4:
            return struct.unpack('!I', data)[0]

    def get_long(self, *args, **kwargs) -> Union[int, None]:
        """ Get long integer from packet. (i.e. long long)

        :return Union[int, None]: long integer
        """

        data = self.get_raw(*args, **kwargs)

        if data and len(data) == 8:
            return struct.unpack('!Q', data)[0]

    def get_tlv(self, *args, **kwargs) -> Any:
        """ Get TLV from packet.

        :return TLVPacket: TLV packet
        """

        return self.__class__(
            buffer=self.get_raw(*args, **kwargs))

    def add_raw(self, type: int, value: bytes) -> None:
        """ Add raw data to packet.

        :param int type: type
        :param bytes value: value
        :return None: None
        """

        self.buffer += struct.pack('!I', type)
        self.buffer += struct.pack('!I', len(value))
        self.buffer += value

    def add_string(self, type: int, value: str) -> None:
        """ Add string to packet.

        :param int type: type
        :param str value: value
        :return None: None
        """

        self.add_raw(type, value.encode())

    def add_short(self, type: int, value: int) -> None:
        """ Add short integer to packet.

        :param int type: type
        :param int value: value
        :return None: None
        """

        self.add_raw(type, struct.pack('!H', value))

    def add_int(self, type: int, value: int) -> None:
        """ Add integer to packet.

        :param int type: type
        :param int value: value
        :return None: None
        """

        self.add_raw(type, struct.pack('!I', value))

    def add_long(self, type: int, value: int) -> None:
        """ Add long integer to packet. (i.e. long long)

        :param int type: type
        :param int value: value
        :return None: None
        """

        self.add_raw(type, struct.pack('!Q', value))

    def add_tlv(self, type: int, value: Any) -> None:
        """ Add TLV packet to packet.

        :param int type: type
        :param Any value: TLV packet
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.add_raw(type, value.buffer)

    def add_from_dict(self, values: dict) -> None:
        """ Add packets from dictionary.

        :param dict values: type as key, value as item
        :return None: None
        """

        for type, value in values.items():
            if isinstance(value, str):
                self.add_string(type, value)
            elif isinstance(value, int):
                self.add_int(type, value)
            elif isinstance(value, self.__class__):
                self.add_tlv(type, value)
            else:
                self.add_raw(type, value)
