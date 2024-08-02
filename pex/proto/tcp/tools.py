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


class TCPTools(object):
    """ Subclass of pex.proto.tcp module.

    This subclass of pex.proto.tcp module is intended for providing
    some TCP tools.
    """

    @staticmethod
    def get_local_host() -> str:
        """ Get local host.

        :return str: local host
        """

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.connect(("8.8.8.8", 53))

            local_host = server.getsockname()[0]
            server.close()

            local_host = local_host

        except Exception:
            local_host = "127.0.0.1"

        return local_host

    def convert_to_local(self, host: str) -> str:
        """ Convert host to local / Parse local host.

        :param str host: host to convert / parse
        :return str: local host
        """

        if host in ['0.0.0.0']:
            return self.get_local_host()

        return host

    @staticmethod
    def check_tcp_port(host: str, port: int, timeout: int = 1) -> bool:
        """ Check if TCP port is opened.

        :param str host: host to check
        :param int port: port to check
        :param int timeout: check timeout
        :return bool: True if opened else False
        """

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            if sock.connect_ex((host, int(port))) == 0:
                return True
        return False
