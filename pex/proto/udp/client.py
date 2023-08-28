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

import socket


class UDPClient(object):
    """ Subclass of pex.proto.udp module.

    This subclass of pex.proto.udp module represents Python
    implementation of the UDP client.
    """

    def __init__(self, host: str, port: int, timeout: int = 10) -> None:
        """ Initialize UDPClient with socket pair.

        :param str host: UDP host
        :param int port: UDP port
        :param int timeout: connection timeout
        :return None: None
        """

        super().__init__()

        self.host = host
        self.port = int(port)

        self.pair = f"{self.host}:{str(self.port)}"

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def send(self, data: bytes) -> None:
        """ Send data to the socket.

        :param bytes data: data to send
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.sendto(data, (self.host, self.port))
        except Exception:
            raise RuntimeError(f"Connection failed for {self.pair}!")

    def recv(self, size: int) -> bytes:
        """ Read data from the socket.

        :param int size: size of data
        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        try:
            return self.sock.recv(size)
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")
