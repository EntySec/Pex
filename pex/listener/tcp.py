#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import socket


class TCPListen:
    def __init__(self, host, port, timeout=10):
        self.host = host
        self.port = int(port)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.client = None
        self.address = []

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(timeout)

    def listen(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)

            return True
        except Exception:
            return False

    def accept(self):
        try:
            self.client, self.address = self.sock.accept()
            return True
        except Exception:
            return False

    def disconnect(self):
        try:
            self.client.close()
            return True
        except Exception:
            return False

    def send(self, data):
        try:
            self.client.send(data)
            return True
        except Exception:
            return False

    def recv(self, size):
        try:
            return self.client.recv(size)
        except Exception:
            return b""


class TCPListener:
    @staticmethod
    def listen_tcp(host, port, timeout=10):
        return TCPListen(host, port, timeout)
