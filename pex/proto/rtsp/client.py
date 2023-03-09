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

from pex.string import String


class RTSPSocket(object):
    def __init__(self, host, port, timeout=10):
        super().__init__()

        self.host = host
        self.port = int(port)

        self.pair = f"rtsp://{self.host}:{str(self.port)}"
        self.string = String()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

    def connect(self):
        try:
            self.sock.connect((self.host, self.port))
        except Exception:
            raise RuntimeError(f"Connection failed for {self.pair}!")

    def disconnect(self):
        try:
            self.sock.close()
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

    def authorize(self, username, password):
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

    def send(self, data):
        try:
            self.sock.send(data)
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

    def recv(self, size):
        try:
            return self.sock.recv(size)
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")


class RTSPClient(object):
    def __init__(self) -> None:
        super().__init__()

    @staticmethod
    def open_rtsp(host, port, timeout=10):
        return RTSPSocket(host, port, timeout)
