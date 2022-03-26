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

import socketserver

import http.server

from pex.tools.http import HTTPTools


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_request(self, fmt, *args):
        return

    def send_status(self, code=200):
        self.send_response(int(code))
        self.send_header("Content-type", "text/html")
        self.end_headers()


class HTTPListen:
    def __init__(self, host, port, methods={}):
        self.http_tools = HTTPTools()
        self.handler = Handler

        self.host = host
        self.port = int(port)

        self.sock = None
        self.methods = methods

    def listen(self):
        try:
            for method in self.methods:
                setattr(self.handler, f"do_{method.upper()}", self.methods[method])

            self.sock = socketserver.TCPServer((host, int(port)), Handler)
            return True
        except Exception:
            return False

    def stop(self):
        try:
            self.sock.server_close()
            return True
        except Exception:
            return False

    def accept(self):
        try:
            self.sock.handle_request()
            return True
        except Exception:
            return False


class HTTPListener:
    @staticmethod
    def listen_http(host, port, methods={}):
        return HTTPListen(host, port, methods)
