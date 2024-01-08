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

import pychromecast
from pychromecast.controllers.youtube import YouTubeController


class ChromecastClient(object):
    """ Subclass of pex.proto.chromecast module.

    This subclass of pex.proto.chromecast module represents Python
    implementation of the Chromecast client.
    """

    def __init__(self, host: str, port: int = 8009) -> None:
        """ Initialize ChromecastClient with socket pair.

        :param str host: Chromecast host
        :param int port: Chromecast port
        :return None: None
        """

        super().__init__()

        self.host = host
        self.port = int(port)

        self.pair = f"{self.host}:{str(self.port)}"

        self.sock = pychromecast.get_chromecast_from_host(
            (self.host, self.port, None, None, None), tries=1)
        self.player = None

    def connect(self) -> None:
        """ Connect to Chromecast socket.

        :return None: None
        """

        self.sock.wait()
        self.player = self.sock.media_controller

    def disconnect(self) -> None:
        """ Disconnect from Chromecast socket.

        :return None: None
        """

        self.sock.disconnect()

    def player_state(self) -> dict:
        """ Return player state.

        :return dict: player state
        :raises RuntimeError: with trailing error message
        """

        if self.player:
            return self.player.status
        raise RuntimeError(f"Player is not available for this device!")

    def play_media(self, url: str, format: str = 'video/mp4') -> None:
        """ Play media file from URL.

        :param str url: URL to video file
        :param str format: video file format
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.player:
            self.player.play_media(url, format)
        else:
            raise RuntimeError(f"Player is not available for this device!")

    def play(self) -> None:
        """ Tap play.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.player:
            self.player.play()
        else:
            raise RuntimeError(f"Player is not available for this device!")

    def pause(self) -> None:
        """ Tap pause.

        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.player:
            self.player.pause()
        else:
            raise RuntimeError(f"Player is not available for this device!")

    def youtube_play(self, id: str) -> None:
        """ Play YouTube video.

        :param str id: YouTube video ID
        :return None: None
        :raises RuntimeError: with trailing error message
        """

        if self.player:
            yt = YouTubeController()
            self.sock.register_handler(yt)
            yt.play_video(id)
        else:
            raise RuntimeError(f"Player is not available for this device!")
