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

from pex.string import String


class RTSPClient(object):
    """ Subclass of pex.proto.rtsp module.

    This subclass of pex.proto.rtsp module represents Python
    implementation of the RTSP client.
    """

    def __init__(self, host: str, port: int, timeout: int = 10) -> None:
        """ Initialize RTSPClient with socket pair.

        :param str host: RTSP host
        :param int port: RTSP port
        :param int timeout: connection timeout
        :return None: None
        """

        super().__init__()

        self.host = host
        self.port = int(port)

        self.pair = f"rtsp://{self.host}:{str(self.port)}"
        self.string = String()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

    def connect(self) -> None:
        """ Connect to RTSP socket.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.connect((self.host, self.port))
        except Exception:
            raise RuntimeError(f"Connection failed for {self.pair}!")

    def disconnect(self) -> None:
        """ Disconnect from RTSP socket.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.close()
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

    def authorize(self, username: str, password: str) -> None:
        """ Authorize in the RTSP socket.

        :param str username: RTSP username
        :param str password: RTSP password
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            request = (
                f"DESCRIBE {self.pair} RTSP/1.0\r\n"
                "CSeq: 2\r\n"
                f"Authorization: Basic {self.string.base64_string(f'{username}:{password}')}\r\n"
                "\r\n"
            )

            self.send(request.encode())
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

    def send(self, data: bytes) -> None:
        """ Send data to the socket.

        :param bytes data: data to send
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.send(data)
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

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
