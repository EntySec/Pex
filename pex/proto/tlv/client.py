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

    def send(self, packet: TLVPacket) -> None:
        """ Send TLV packet to the socket.

        :param TLVPacket packet: TLV packet
        :return None: None
        """

        if self.client:
            self.client.send(packet.buffer)

    def read(self) -> TLVPacket:
        """ Read TLV packet from the socket.

        :return TLVPacket: read TLV packet
        """

        self.client.setblocking(False)
        buffer = b''

        while True:
            try:
                buffer += self.client.recv(self.max_size)
            except Exception:
                if buffer:
                    break

        return TLVPacket(buffer=buffer, endian=self.endian)
