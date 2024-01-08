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

import requests
import socket
import urllib3

from typing import Any, Union

from .tools import HTTPTools


class HTTPClient(object):
    """ Subclass of pex.proto.http module.

    This subclass of pex.proto.http module represents Python
    implementation of the HTTP socket.
    """

    def __init__(self) -> None:
        super().__init__()

        self.http_tools = HTTPTools()

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def http_request(self, method: str, host: str, port: int, path: str = '/', ssl: bool = False, timeout: int = 10,
                     output: bool = True, session: Any = requests, **kwargs) -> Union[str, None]:
        """ Send HTTP request.

        :param str method: HTTP method (GET, POST, DELETE, HEAD, OPTIONS)
        :param str host: HTTP host
        :param int port: HTTP port
        :param str path: HTTP path
        :param bool ssl: True if HTTP uses SSL else False
        :param int timeout: connection timeout
        :param bool output: True if wait for output else False
        :param Any session: request handler
        :return Union[str, None]: output if output is True else None
        """

        if not output:
            timeout = 0

        kwargs.setdefault("timeout", timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", True)

        if not ssl:
            ssl = int(port) in [443]

        url = self.http_tools.normalize_url(host, port, path, ssl)

        try:
            return getattr(session, method.lower())(url, **kwargs)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            raise RuntimeError(f"Invalid URL schema in {url}!")
        except requests.exceptions.ConnectionError:
            raise RuntimeError(f"Connection failed for {url}!")
        except Exception:
            return None
