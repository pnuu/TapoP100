"""Module for controlling Tapo L530 light bulbs."""

import logging

from PyP100._base import TapoBase
from PyP100.utils import get_set_device_info_payload

LOGGER = logging.getLogger(__name__)


class L530(TapoBase):
    """Control Tapo L530 light bulbs."""

    def set_brightness(self, brightness):
        """Set brightness level.

        Valid range is integers from 1 to 100.
        """
        self.turn_on()
        payload = self._get_secure_payload(
            get_set_device_info_payload(self._terminal_uuid, params={"brightness": brightness})
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

    def set_color_temperature(self, colortemp):
        """Set color temperature of white light.

        Valid range is from 2500 K to 6500 K.
        """
        self.turn_on()
        payload = self._get_secure_payload(
            get_set_device_info_payload(self._terminal_uuid, params={"color_temp": colortemp})
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

    def set_hsv(self, hue, saturation, value):
        """Set hue, saturation and value.

        Valid ranges are:
        - hue: 0 to 360 degrees
        - saturation: 0 to 100 %
        - value: 0 to 100 %
        """
        self.set_color_temperature(0)
        self.turn_on()
        payload = self._get_secure_payload(
            get_set_device_info_payload(
                self._terminal_uuid,
                params={
                    "hue": hue,
                    "saturation": saturation,
                    "brightness": value})
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

    def set_rgb(self, red, green, blue):
        """Set RGB colors.

        Valid ranges are from 0 to 255 for each component.
        """
        rgb = RGB2HSV(red, green, blue)
        if rgb.value == 0:
            self.turn_off()
        else:
            self.set_hsv(rgb.hue, rgb.saturation, rgb.value)


class RGB2HSV:
    """Convert RGB values to HSV."""

    def __init__(self, red, green, blue):
        """Initialize the class."""
        self.red = red / 255.
        self.green = green / 255.
        self.blue = blue / 255.
        self._c_max = max(self.red, self.green, self.blue)
        self._c_min = min(self.red, self.green, self.blue)
        self._delta = self._c_max - self._c_min
        self.hue = self._get_hue()
        self.saturation = self._get_saturation()
        self.value = self._get_value()

    def _get_hue(self):
        if self._delta == 0:
            hue = 0
        elif self._c_max == self.red:
            hue = ((self.green - self.blue) / self._delta) % 6
        elif self._c_max == self.green:
            hue = (self.blue - self.red) / self._delta + 2
        else:
            hue = (self.red - self.green) / self._delta + 4

        return int(60 * hue)

    def _get_saturation(self):
        return 0 if self._c_max == 0 else int(100 * self._delta / self._c_max)

    def _get_value(self):
        return int(100 * self._c_max)
