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

import socket

from .packet import TLVPacket


class TLVClient(object):
    """ Subclass of pex.proto.tlv module.

    This subclass of pex.proto.tlv module represents Python
    implementation of the TLV client.
    """

    def __init__(self, client: socket.socket, endian: str = 'little', max_size: int = 4096) -> None:
        """ Initialize TLVClient with socket.

        :param socket.socket client: socket
        :return None: None
        """

        super().__init__()

        self.client = client
        self.endian = endian
        self.max_size = max_size

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

    def read(self) -> TLVPacket:
        """ Read TLV packet from the socket.

        :return TLVPacket: read TLV packet
        :raises RuntimeError: with trailing error message
        """

        if not self.client:
            raise RuntimeError("Socket is not connected!")

        buffer = self.read_raw(4)
        length = self.read_raw(4)

        buffer += length
        length = int.from_bytes(length, self.endian)

        value = b''

        while length > 0:
            chunk = self.read_raw(length)
            value += chunk
            length -= len(chunk)

        buffer += value

        return TLVPacket(buffer=buffer, endian=self.endian)

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
