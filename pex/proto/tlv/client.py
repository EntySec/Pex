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
import socket

from typing import Union
from .packet import TLVPacket


class TLVClient(object):
    """ Subclass of pex.proto.tlv module.

    This subclass of pex.proto.tlv module represents Python
    implementation of the TLV client.
    """

    def __init__(self, client: socket.socket, block: bool = True) -> None:
        """ Initialize TLVClient with socket.

        :param socket.socket client: socket
        :param bool block: True to block socket else False
        :return None: None
        """

        super().__init__()

        self.block = block
        self.client = client

    def close(self) -> None:
        """ Close connected socket.

        :return None: None
        """

        if self.client:
            self.client.close()

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet to the socket.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        self.send_raw(packet.buffer)

    def read(self) -> Union[TLVPacket, None]:
        """ Read TLV packet from the socket.

        :return Union[TLVPacket, None]: read TLV packet
        (returns None in case of blocking I/O)
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        self.client.setblocking(self.block)

        try:
            buffer = self.read_raw(4)
        except socket.error, e:
            if e.errno == errno.EAGAIN:
                return

        self.client.setblocking(True)
        length = self.read_raw(4)

        buffer += length
        length = struct.unpack('!I', length)[0]

        value = b''

        while length > 0:
            chunk = self.read_raw(length)
            value += chunk
            length -= len(chunk)

        buffer += value

        return TLVPacket(buffer=buffer)

    def send_raw(self, data: bytes) -> None:
        """ Send raw data instead of TLV packet.

        :param bytes data: data to send
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        self.client.send(data)

    def read_raw(self, size: int) -> bytes:
        """ Read raw data instead of TLV packet.

        :param int size: size of data to read
        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        return self.client.recv(size)
