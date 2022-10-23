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

    def set_hue_saturation_value(self, hue, saturation, value):
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
