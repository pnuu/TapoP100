"""Base module for TP-Link Tapo devices."""

import ast
from base64 import b64decode
import json
import logging
import time
import uuid

from requests import Session

from PyP100.utils import get_response_with_retries
from PyP100.utils import get_set_device_info_payload

ERROR_CODES = {
    "0": "Success",
    "-1010": "Invalid Public Key Length",
    "-1012": "Invalid terminalUUID",
    "-1501": "Invalid Request or Credentials",
    "1002": "Incorrect Request",
    "-1003": "JSON formatting error",
    "-1008": "Invalid value",
}

LOGGER = logging.getLogger(__name__)


class TapoCommunication:
    """Base methods for communication with Tapo devices."""

    _session = Session()

    def _get_response(self, url, payload):
        response = get_response_with_retries(self._session, url, payload, headers=self._headers)
        return self._tplink_cipher.decrypt(response.json()["result"]["response"])

    def _get_secure_payload(self, payload):
        return {
            "method": "securePassthrough",
            "params": {
                "request": self._tplink_cipher.encrypt(json.dumps(payload))
            }
        }

    def get_device_info(self):
        """Retrieve current settings from the device."""
        payload = self._get_secure_payload(
            _get_device_info_payload()
        )

        response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)

        return json.loads(response)


class TapoBase(TapoCommunication):
    """Base class for TP-Link Tapo devices."""

    def __init__(self, ip_address, token, cipher):
        """Initialize the class."""
        self.ip_address = ip_address
        self._token = token
        self._tplink_cipher = cipher
        self._terminal_uuid = str(uuid.uuid4())
        self._headers = None

    def turn_on(self):
        """Power on the device."""
        payload = self._get_secure_payload(
            get_set_device_info_payload(self._terminal_uuid, params={"device_on": True})
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

    def _log_errors(self, response):
        if ast.literal_eval(response)["error_code"] != 0:
            error_code = ast.literal_eval(response)["error_code"]
            error_message = ERROR_CODES[str(error_code)]
            LOGGER.error(f"Error code: {error_code}, {error_message}")

    def turn_off(self):
        """Power off the device."""
        payload = self._get_secure_payload(
            get_set_device_info_payload(self._terminal_uuid, params={"device_on": False})
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

    def toggle_power(self):
        """Toggle device on/off."""
        if self.get_device_info()["result"]["device_on"]:
            self.turn_off()
        else:
            self.turn_on()

    def get_device_name(self):
        """Get the device name."""
        data = self.get_device_info()

        if data["error_code"] != 0:
            error_code = ast.literal_eval(data)["error_code"]
            error_message = ERROR_CODES[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")
        else:
            encoded_name = data["result"]["nickname"]
            name = b64decode(encoded_name)
            return name.decode("utf-8")

    def turn_on_with_delay(self, delay):
        """Switch on the device with a time delay."""
        payload = self._get_secure_payload(
            self._get_add_countdown_rule_payload(delay, True)
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

    def _get_add_countdown_rule_payload(self, delay, state):
        return {
            "method": "add_countdown_rule",
            "params": {
                "delay": int(delay),
                "desired_states": {
                    "on": state
                },
                "enable": True,
                "remain": int(delay)
            },
            "terminalUUID": self._terminal_uuid
        }

    def turn_off_with_delay(self, delay):
        """Switch off the device with a time delay."""
        payload = self._get_secure_payload(
            self._get_add_countdown_rule_payload(delay, False)
        )

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)


def _get_device_info_payload():
    return {
        "method": "get_device_info",
        "requestTimeMils": int(round(time.time() * 1000)),
    }
