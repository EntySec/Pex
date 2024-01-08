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

from pysnmp.entity.rfc3413.oneliner import cmdgen


class SNMPClient(object):
    """ Subclass of pex.proto.snmp module.

    This subclass of pex.proto.snmp module represents Python
    implementation of the SNMP client.
    """

    def __init__(self, host: str, port: int, timeout: int = 15) -> None:
        """ Initialize SNMPClient with socket pair.

        :param str host: SNMP host
        :param int port: SNMP port
        :param int timeout: connection timeout
        :return None: None
        """

        super().__init__()

        self.host = host
        self.port = int(port)

        self.pair = f"{self.host}:{str(self.port)}"
        self.timeout = float(timeout)

    def get(self, community: str, oid: str, version: int = 1, retries: int = 0) -> bytes:
        """ Get OID from SNMP server.

        :param str community: SNMP server community string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """

        cmd_gen = cmdgen.CommandGenerator()

        try:
            err_ind, err_stat, err_i, var_binds = cmd_gen.getcmd(
                cmdgen.CommunityData(community, mp_model=version),
                cmdgen.UdpTransportTarget((self.host, self.port), timeout=self.timeout, retries=retries),
                oid
            )
        except Exception:
            raise RuntimeError(f"Connection failed for {self.pair}!")

        if not err_ind or not err_stat:
            return var_binds
        raise RuntimeError(f"Invalid community string in {community}!")
