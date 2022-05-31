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
import ssl
from OpenSSL import crypto


class OpenSSL:
    """ Subclass of pex.ssl module.

    This subclass of pex.ssl module is intended for providing
    Python realization of OpenSSL library.
    """

    def wrap_client(self, client: socket.socket, keyfile: str = 'hatsploit.key', certfile: str = 'hatsploit.crt',
                    protocol: ssl._SSLMethod = ssl.PROTOCOL_TLS, expire: int = 365, nodename: str = 'HatSploit',
                    country: str = 'US', state: str = 'HatSploit', location: str = 'HatSploit',
                    organization: str = 'HatSploit', unit: str = 'HatSploit') -> ssl.SSLSocket:
        """ Generate a certificate and wrap a socket with it.

        :param socket.socket client: socket client
        :param str keyfile: path to the output key file
        :param str certfile: path to the output certificate file
        :param ssl._SSLMethod protocol: protocol type
        :param int expire: certificate expiration limit
        :param str nodename: certificate nodename
        :param str country: certificate country
        :param str state: certificate state
        :param str location: certificate location
        :param str organization: certificate organization
        :param str unit: certificate unit
        :return ssl.SSLSocket: wrapped socket
        """

        key = self.generate_key()
        cert = self.generate_cert(
            key,
            expire=expire,
            nodename=nodename,
            country=country,
            state=state,
            location=location,
            organization=organization,
            unit=unit
        )

        self.write_key(key, keyfile)
        self.write_cert(cert, certfile)

        return ssl.wrap_socket(
            client,
            server_side=True,
            certfile=certfile,
            keyfile=keyfile,
            ssl_version=protocol
        )

    def write_key(self, key: crypto.PKey, filename: str) -> None:
        """ Write generated key to a file.

        :param crypto.PKey key: generated key to write
        :param str filename: name of file to write to
        :return None: None
        """

        with open(filename, 'wb') as f:
            f.write(self.dump_key(key))

    def write_cert(self, cert: crypto.X509, filename: str) -> None:
        """ Write generated certificate to a file.

        :param crypto.X509 cert: generated certificate to write
        :param str filename: name of file to write to
        :return None: None
        """

        with open(filename, 'wb') as f:
            f.write(self.dump_cert(cert))

    @staticmethod
    def dump_key(key: crypto.PKey) -> bytes:
        """ Dump generated key contents.

        :param crypto.PKey key: generated key to dump
        :return bytes: generated key contents
        """

        pem_type = crypto.FILETYPE_PEM
        return crypto.dump_privatekey(pem_type, key)

    @staticmethod
    def dump_cert(cert: crypto.X509) -> bytes:
        """ Dump generated certificate contents.

        :param crypto.X509 cert: generated certificate to dump
        :return bytes: generated certificate contents
        """

        pem_type = crypto.FILETYPE_PEM
        return crypto.dump_certificate(pem_type, cert)

    @staticmethod
    def generate_key() -> crypto.PKey:
        """ Generate key.

        :return crypto.PKey: generated key
        """

        rsa_type = crypto.TYPE_RSA

        key = crypto.PKey()
        key.generate_key(rsa_type, 2048)

        return key

    @staticmethod
    def generate_cert(key: crypto.PKey, expire: int = 365, nodename: str = 'HatSploit', country: str = 'US',
                      state: str = 'HatSploit', location: str = 'HatSploit', organization: str = 'HatSploit',
                      unit: str = 'HatSploit') -> crypto.X509:
        """ Generate certificate.

        :param crypto.PKey key: generated key
        :param int expire: certificate expiration limit
        :param str nodename: certificate nodename
        :param str country: certificate country
        :param str state: certificate state
        :param str location: certificate location
        :param str organization: certificate organization
        :param str unit: certificate unit
        :return crypto.X509: generated certificate
        """

        cert = crypto.X509()
        cert.get_subject().CN = nodename
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = location
        cert.get_subject().O = organization
        cert.get_subject().OU = unit

        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expire * 24 * 60 * 60)

        cert.set_serial_number(0)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)

        cert.sign(key, "sha512")

        return cert
