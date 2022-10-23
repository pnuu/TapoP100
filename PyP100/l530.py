"""Module for controlling Tapo L530 light bulbs."""

import logging

from PyP100._base import TapoBase

LOGGER = logging.getLogger(__name__)


class L530(TapoBase):
    """Control Tapo L530 light bulbs."""

    def set_brightness(self, brightness):
        """Set brightness level.

        Valid range is integers from 1 to 100.
        """
        self.turn_on()
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"brightness": brightness})
        )

        try:
            response = self._get_response(url, payload)
        finally:
            self._log_errors(response)

    def set_color_temperature(self, colortemp):
        """Set color temperature of white light.

        Valid range is from 2500 K to 6500 K.
        """
        self.turn_on()
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"color_temp": colortemp})
        )

        try:
            response = self._get_response(url, payload)
        finally:
            self._log_errors(response)

    def set_hue_saturation(self, hue, saturation):
        """Set hue and saturation.

        Valid range for both is from 0 to 100.
        """
        self.set_color_temperature(0)
        self.turn_on()
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"hue": hue, "saturation": saturation})
        )

        try:
            response = self._get_response(url, payload)
        finally:
            self._log_errors(response)
