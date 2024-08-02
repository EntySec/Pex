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

from typing import Callable, Any
from alive_progress import alive_bar

from pex.string import String


class BashEcho(object):
    """ Subclass of pex.post.push module.

    This subclass of pex.post.push module is intended for providing
    implementation of bash echo method of pushing file to sender.
    """

    def __init__(self, sender: Callable[..., Any],
                 config: dict = {}) -> None:
        """ Initialize bash_echo method.

        :param Callable[..., Any] sender: sender to execute commands on
        :param dict config: configuration for method
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        self.sender = sender

        self.config = {
            'path': '/tmp',
            'location': None,
            'linemax': 1024,
            'data': b'',
            'concat': ' ; ',
            'background': True,
            'delete': True,
            'args': None,
            'interpreter': None,
            'debug': False
        }
        self.config.update(config)

        self.config['location'] = self.config['location'] or \
            self.config['path'] + '/' + String().random_string(8)

    def exec(self) -> None:
        """ Execute pushed file.

        :return None: None
        """

        if self.config['interpreter']:
            cmds = [
                f"{self.config['interpreter']}"
                f"{self.config['location']}"
                f"{' ' + self.config['args'] if self.config['args'] else ''}"
                f"{' & echo' if self.config['background'] else ''}"
            ]
        else:
            cmds = [
                f"chmod 777 {self.config['location']}",
                f"{self.config['location']}"
                f"{' ' + self.config['args'] if self.config['args'] else ''}"
                f"{' & echo' if self.config['background'] else ''}"
            ]

        if self.config['delete']:
            cmds.append(f"rm -f {self.config['location']}")

        command = self.config['concat'].join(cmds)

        if self.config['debug']:
            print(command)

        self.sender(command)

    def push(self) -> str:
        """ Push file to sender using bash echo method.

        :return str: location of new file
        """

        data = self.config['data']

        echo_stream = "echo -en '{}' >> {}"
        echo_max_length = self.config['linemax']

        size = len(data)
        num_parts = int(size / echo_max_length) + 1

        with alive_bar(num_parts, receipt=False, ctrl_c=False, title="Pushing") as bar:
            for i in range(0, num_parts):
                bar()

                current = i * echo_max_length
                block = String().bytes_to_octal(data[current:current + echo_max_length], True)

                if block:
                    command = echo_stream.format(block, self.config['location'])
                    self.sender(command)

        return self.config['location']
