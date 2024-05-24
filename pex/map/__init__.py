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

from typing import Tuple

MAPS = {
    'world': {
        'corners': (1, 4, 23, 73),
        'data': r'''
                       . _..::__:  ,-"-"._       |7       ,     _,.__     
       _.___ _ _<_>`!(._`.`-.    /        _._     `_ ,_/  '  '-._.---.-.__
     .{     " " `-==,',._\{  \  / {)     / _ ">_,-' `                 .--?_
      \_.:--.       `._ )`^-. "'      , [_/(                       __,/-' 
     '"'     \         "    _L       oD_,--'                )     /. (|   
              |           ,'         _)_.\\._<> 6              _,' /  '   
              `.         /          [_/_'` `"(                <'}  )      
               \\    .-. )          /   `-'"..' `:._          _)  '       
        `        \  (  `(          /         `:\  > \  ,-^.  /' '         
                  `._,   ""        |           \`'   \|   ?_)  {\         
                     `=.---.       `._._       ,'     "`  |' ,- '.        
                       |    `-._        |     /          `:`<_|h--._      
                       (        >       .     | ,          `=.__.`-'\     
                        `.     /        |     |{|              ,-.,\     .
                         |   ,'          \   / `'            ,"     \     
                         |  /             |_'                |  __  /     
                         | |                                 '-'  `-'   \.
                         |/                                        "    / 
                         \.                                            '  

'''
    }
}


class Map(object):
    """ Main class of pex.map module.

    This main class of pex.map module is intended to provide
    an interface for plotting ASCII map
    """

    def __init__(self, map_name: str = 'world', dot: str = '*') -> None:
        """ Initialise map.

        :param str map_name: map name
        :return None: None
        """

        self.map = MAPS[map_name]
        self.data = self.map['data'].splitlines()
        self.dot = dot

    def location(self, latitude: float, longitude: float) -> Tuple[int, int]:
        """ Convert latitude and longitude to coordinates.

        :param float latitude: latitude
        :param float longitude: longitude
        :return Tuple[int, int]: x, y
        """

        corners = self.map['corners']

        width = corners[3] - corners[1]
        height = corners[2] - corners[0]

        abs_latitude = -latitude + 90
        abs_longitude = longitude + 180

        x = (abs_longitude / 360.0) * width + corners[1]
        y = (abs_latitude / 180.0) * height + corners[0]

        return int(x), int(y)

    def deploy(self, latitude: float, longitude: float) -> None:
        """ Deploy location on map.

        :param float latitude: latitude
        :param float longitude: longitude
        :return None: None
        """

        x, y = self.location(latitude, longitude)
        self.data[y] = self.data[y][:x] + self.dot + self.data[y][x + 1:]

    def get_map(self) -> str:
        """ Get map.

        :return str: map
        """

        return '\n'.join(self.data)
