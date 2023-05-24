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

import re
import selectors
import sys
import telnetlib
import time

import socket

from typing import Optional, Union, Callable, Any

from .tools import ChannelTools


class ChannelClient(object):
    """ Subclass of pex.proto.channel module.

    This subclass of pex.proto.channel module represents Python
    implementation of the channel client.
    """

    def __init__(self, client: socket.socket) -> None:
        """ Initialize ChannelClient with socket

        :param socket.socket client: socket
        :return None: None
        """

        super().__init__()

        self.channel_tools = ChannelTools()

        self.sock = telnetlib.Telnet()
        self.sock.sock = client

        self.terminated = False

        self.read_size = 1024 ** 2
        self.read_delay = 1

        self.stashed = b""

    def stash(self) -> bytes:
        """ Return stashed data.

        :return bytes: stashed data
        """

        stashed_data = self.stashed
        self.stashed = b""

        return stashed_data

    def disconnect(self) -> None:
        """ Disconnect connected socket.

        :return None: None
        """

        if self.sock.sock:
            self.sock.close()

    def send(self, data: bytes) -> None:
        """ Send data to the channel socket.

        :param bytes data: data to send
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            return self.sock.sock.send(data)
        raise RuntimeError("Socket is not connected!")

    def read(self, size: int) -> bytes:
        """ Read data from the channel socket.

        :param int size: size of data
        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            return self.sock.sock.recv(size)
        raise RuntimeError("Socket is not connected!")

    def readall(self) -> bytes:
        """ Read all possible data from the channel socket.

        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            result = self.stash()
            self.sock.sock.setblocking(False)

            while True:
                try:
                    data = self.read(self.read_size)

                except Exception:
                    if result:
                        break
                    continue

                result += data
                time.sleep(self.read_delay)

            self.sock.sock.setblocking(True)
            return result

        raise RuntimeError("Socket is not connected!")

    def print_until(self, token: str, printer: Callable[..., Any] = print) -> None:
        """ Read and print data until specific token.

        :param str token: token to read data until
        :param Callable[..., Any] printer: function that prints data
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            token = token.encode()
            data = self.stash().decode(errors='ignore')

            if printer != print:
                printer(data, start='', end='')
            else:
                printer(data, end='')

            while True:
                data = self.read(self.read_size)
                block, stash = self.channel_tools.token_extract(data, token)

                if printer != print:
                    printer(block.decode(errors='ignore'), start='', end='')
                else:
                    printer(block.decode(errors='ignore'), end='')

                if block != data:
                    self.stashed = stash
                    break
        else:
            raise RuntimeError("Socket is not connected!")

    def read_until(self, token: str) -> bytes:
        """ Read data from the channel socket until specific token.

        :param str token: token to read data until
        :return bytes: read data
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            token = token.encode()
            result = self.stash()

            while True:
                data = self.read(self.read_size)
                block, stash = self.channel_tools.token_extract(data, token)

                result += block

                if block != data:
                    self.stashed = stash
                    break

            return result
        raise RuntimeError("Socket is not connected!")

    def send_command(self, command: str, output: bool = True) -> Union[str, None]:
        """ Send command to the channel socket.

        :param str command: command to send
        :param bool output: True if wait for output else False
        :return Union[str, None]: output if output is True else None
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            try:
                buffer = command.encode()
                self.send(buffer)

                if output:
                    data = self.readall()
                    data = data.decode(errors='ignore')

                    return data
            except Exception:
                self.terminated = True
                raise RuntimeError("Channel closed connection unexpectedly!")
            return None
        raise RuntimeError("Socket is not connected!")

    def send_token_command(self, command: str, token: str, output: bool = True,
                           printer: Optional[Callable[..., Any]] = None) -> Union[str, None]:
        """ Send command and read output until specific token.

        :param str command: command to send
        :param str token: token to read data until
        :param bool output: True if wait for output else False
        :param Optional[Callable[..., Any]] printer: function to print data,
        None for not printing but returning read data
        :return Union[str, None]: output if output is True and printer is None else None
        """

        if self.sock.sock:
            try:
                buffer = command.encode()
                self.send(buffer)

                if printer:
                    self.print_until(token, printer)
                else:
                    data = self.read_until(token)

                    if output:
                        data = data.decode(errors='ignore')
                        return data

            except Exception:
                self.terminated = True
                raise RuntimeError("Channel closed connection unexpectedly!")

            return None
        raise RuntimeError("Socket is not connected!")

    def interact(self, terminator: str = '\n') -> None:
        """ Interact with the channel socket.

        :param str terminator: data to send after each command
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.sock.sock:
            selector = selectors.SelectSelector()

            selector.register(self.sock, selectors.EVENT_READ)
            selector.register(sys.stdin, selectors.EVENT_READ)

            while True:
                for key, events in selector.select():
                    if key.fileobj is self.sock:
                        try:
                            response = self.stash() + self.sock.read_eager()
                        except Exception:
                            self.terminated = True
                            raise RuntimeError("Channel closed connection unexpectedly!")

                        if response:
                            print(response.decode(errors='ignore'), end='')

                    elif key.fileobj is sys.stdin:
                        line = sys.stdin.readline().strip()
                        if not line:
                            pass
                        if line == "quit":
                            return
                        self.sock.write((line + terminator).encode())
        else:
            raise RuntimeError("Socket is not connected!")
