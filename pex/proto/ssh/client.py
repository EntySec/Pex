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

import paramiko

from typing import Optional


class SSHClient(object):
    """ Subclass of pex.proto.ssh module.

    This subclass of pex.proto.ssh module represents Python
    implementation of the SSH client.
    """

    def __init__(self, host: str, port: int, username: Optional[str] = None,
                 password: Optional[str] = None, timeout: int = 10) -> None:
        """ Initialize SSHClient with socket pair and credentials.

        :param str host: SSH host
        :param int port: SSH port
        :param Optional[str] username: SSH username
        :param Optional[str] password: SSH password
        :param int timeout: connection timeout
        :return None: None
        """

        super().__init__()

        self.host = host
        self.port = int(port)

        self.pair = f"{self.host}:{str(self.port)}"

        self.username = username
        self.password = password
        self.timeout = timeout

        self.sock = paramiko.SSHClient()
        self.sock.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self) -> None:
        """ Connect to SSH socket.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
        except paramiko.AuthenticationException:
            raise RuntimeError(f"Authentication via {self.username}:{self.password} failed for {self.pair}!")
        except Exception:
            raise RuntimeError(f"Connection failed for {self.pair}!")

    def disconnect(self) -> None:
        """ Disconnect from SSH socket.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        try:
            self.sock.close()
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")

    def send_command(self, command: str) -> str:
        """ Send command to the SSH socket.

        :param str command: command to send
        :return str: command output
        :raises RuntimeError: with trailing error message
        """

        try:
            return self.sock.exec_command(command)
        except Exception:
            raise RuntimeError(f"Socket {self.pair} is not connected!")
