"""Module for controlling Tapo L530 light bulbs."""

from PyP100 import PyP100

import json
import logging
import time
import ast

_LOGGER = logging.getLogger(__name__)


class L530(PyP100.P100):
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

        response = self._get_response(url, payload)

        if ast.literal_eval(response)["error_code"] != 0:
            error_code = ast.literal_eval(response)["error_code"]
            error_message = self._error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")

    def set_color_temperature(self, colortemp):
        """Set color temperature of white light.

        Valid range is from 2500 K to 6500 K.
        """
        self.turn_on()
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"color_temp": colortemp})
        )

        response = self._get_response(url, payload)

        if ast.literal_eval(response)["error_code"] != 0:
            error_code = ast.literal_eval(response)["error_code"]
            error_message = self._error_codes[str(error_code)]
            print(error_message)

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

        response = self._get_response(url, payload)

        if ast.literal_eval(response)["error_code"] != 0:
            error_code = ast.literal_eval(response)["error_code"]
            error_message = self._error_codes[str(error_code)]
            print(error_message)
