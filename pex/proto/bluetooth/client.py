"""
MIT License

Copyright (c) 2020-2023 EntySec

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

import binascii
import time
from bluepy.btle import Scanner, DefaultDelegate


class BTLEOptions(object):
    def __init__(self, buffering, mac, enum_services):
        super().__init__()

        self.buffering = buffering
        self.mac = mac
        self.enum_services = enum_services


class ScanDelegate(DefaultDelegate):
    def __init__(self, options):
        DefaultDelegate.__init__(self)
        self.options = options

    def handleDiscovery(self, dev, isNewDev, isNewData):
        if not isNewDev:
            return

        elif self.options.mac and dev.addr != self.options.mac:
            return

        if self.options.buffering:
            dev.print_info()


class BTLEScanner(Scanner):
    def __init__(self, mac=None, iface=0):
        Scanner.__init__(self, iface)
        self.mac = mac

    def _decode_address(self, resp):
        addr = binascii.b2a_hex(resp["addr"][0]).decode("utf-8")
        return ":".join([addr[i:i + 2] for i in range(0, 12, 2)])

    def _find_or_create(self, addr):
        if addr in self.scanned:
            dev = self.scanned[addr]
        else:
            dev = Device(addr, self.iface)
            self.scanned[addr] = dev

        return dev

    def process(self, timeout=10.0):
        start = time.time()

        while True:
            if timeout:
                remain = start + timeout - time.time()
                if remain <= 0.0:
                    break
            else:
                remain = None

            resp = self._waitResp(["scan", "stat"], remain)
            if resp is None:
                break

            respType = resp["rsp"][0]

            if respType == "stat":
                if resp["state"][0] == "disc":
                    self._mgmtCmd("scan")

            elif respType == "scan":
                addr = self._decode_address(resp)

                if not self.mac or addr == self.mac:
                    dev = self._find_or_create(addr)

                    newData = dev._update(resp)

                    if self.delegate:
                        self.delegate.handleDiscovery(dev, (dev.updateCount <= 1), newData)

                    if self.mac and dev.addr == self.mac:
                        break


class BluetoothClient:
    def btle_scan(self, buffering=False, enum_services=False, time=10, mac=None):
        options = BTLEOptions(buffering, mac, enum_services)
        scanner = BTLEScanner(mac).withDelegate(ScanDelegate(options))

        try:
            return [result for result in scanner.scan(time)]
        except Exception:
            return None
