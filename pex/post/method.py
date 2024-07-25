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

from typing import (
    NamedTuple,
    Any,
    Union,
    Optional
)

from pex.platform import Platform


class Method(NamedTuple):
    name: str
    platform: Platform
    handler: Any
    uri: bool


def select_method(methods: list, platform: Optional[Union[Platform, str]] = None,
                  method: str = '') -> Union[Method, None]:
    """ Select appropriate method for platform
    or check if method compatible.

    :param list methods: list of methods
    :param Optional[Union[Platform, str]] platform: platform to check compatibility with
    :param str method: method to check if presented
    :return Method: method
    """

    if not platform:
        return methods[0]

    for _method in methods:
        if method == _method.name and \
                platform in _method.platform:
            return _method

    for _method in methods:
        if platform in _method.platform:
            return _method
