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
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "set_device_info",
            "params": {
                "brightness": brightness
            },
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self.cookie
        }

        encrypted_payload = self.tplink_cipher.encrypt(json.dumps(payload))

        secure_passthrough_payload = {
            "method": "securePassthrough",
            "params": {
                "request": encrypted_payload
            }
        }

        r = self.session.post(url, json=secure_passthrough_payload, headers=headers, timeout=2)

        decrypted_response = self.tplink_cipher.decrypt(r.json()["result"]["response"])

        if ast.literal_eval(decrypted_response)["error_code"] != 0:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")

    def set_color_temperature(self, colortemp):
        """Set color temperature of white light.

        Valid range is from 2500 K to 6500 K.
        """
        self.turn_on()
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "set_device_info",
            "params": {
                "color_temp": colortemp
            },
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self.cookie
        }

        encrypted_payload = self.tplink_cipher.encrypt(json.dumps(payload))

        secure_passthrough_payload = {
            "method": "securePassthrough",
            "params": {
                "request": encrypted_payload
            }
        }

        r = self.session.post(url, json=secure_passthrough_payload, headers=headers, timeout=2)

        decrypted_response = self.tplink_cipher.decrypt(r.json()["result"]["response"])

        if ast.literal_eval(decrypted_response)["error_code"] != 0:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            print(error_message)

    def set_hue_saturation(self, hue, saturation):
        """Set hue and saturation.

        Valid range for both is from 0 to 100.
        """
        self.set_color_temperature(0)
        self.turn_on()
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "set_device_info",
            "params": {
                "hue": hue,
                "saturation": saturation
            },
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self.cookie
        }

        encrypted_payload = self.tplink_cipher.encrypt(json.dumps(payload))

        secure_passthrough_payload = {
            "method": "securePassthrough",
            "params": {
                "request": encrypted_payload
            }
        }

        r = self.session.post(url, json=secure_passthrough_payload, headers=headers, timeout=2)

        decrypted_response = self.tplink_cipher.decrypt(r.json()["result"]["response"])

        if ast.literal_eval(decrypted_response)["error_code"] != 0:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            print(error_message)
