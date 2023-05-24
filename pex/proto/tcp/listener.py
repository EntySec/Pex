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


class TCPListener(object):
    """ Subclass of pex.proto.tcp module.

    This subclass of pex.proto.tcp module represents Python
    implementation of TCP listener.
    """

    def __init__(self, host: str, port: int, timeout: int = 10) -> None:
        """ Start TCP listener on socket pair.

        :param str host: host to listen
        :param int port: port to listen
        :param int timeout: listener timeout
        :return None: None
        """

        super().__init__()

        self.host = host
        self.port = int(port)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.client = None
        self.address = []

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(timeout)

    def listen(self) -> None:
        """ Start TCP listener.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
        except Exception:
            raise RuntimeError(f"Failed to start TCP listener on port {str(self.port)}!")

    def stop(self) -> None:
        """ Stop TCP listener.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.close()
        except Exception:
            raise RuntimeError("TCP listener is not started!")

    def accept(self) -> None:
        """ Accept connection.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.client, self.address = self.sock.accept()
        except Exception:
            raise RuntimeError("TCP listener is not started!")

    def disconnect(self) -> None:
        """ Disconnect connected socket.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.client.close()
        except Exception:
            raise RuntimeError(f"Socket {self.address[0]}:{self.address[1]} is not connected!")

    def send(self, data: bytes) -> None:
        """ Send data to the connected socket.

        :param bytes data: data to send
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.client.send(data)
        except Exception:
            raise RuntimeError(f"Socket {self.address[0]}:{self.address[1]} is not connected!")

    def recv(self, size: int) -> bytes:
        """ Read data from the connected socket.

        :param int size: size of data
        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        try:
            return self.client.recv(size)
        except Exception:
            raise RuntimeError(f"Socket {self.address[0]}:{self.address[1]} is not connected!")
