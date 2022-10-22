"""Module for handling Tapo P100 sockets."""

import logging

import requests
from requests import Session

from base64 import b64decode
import hashlib
from Crypto.PublicKey import RSA
import time
import json
from Crypto.Cipher import PKCS1_v1_5
from . import tp_link_cipher
import ast
import uuid

LOGGER = logging.getLogger(__name__)


# Old Functions to get device list from tplinkcloud
def get_token(email, password):
    """Get login token."""
    url = "https://eu-wap.tplinkcloud.com"
    payload = {
        "method": "login",
        "params": {
            "appType": "Tapo_Ios",
            "cloudUserName": email,
            "cloudPassword": password,
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2"
        }
    }

    return requests.post(url, json=payload).json()['result']['token']


def get_device_list(email, password):
    """Get list of devices from TP-Link cloud."""
    url = "https://eu-wap.tplinkcloud.com?token=" + get_token(email, password)
    payload = {
        "method": "getDeviceList",
    }

    return requests.post(url, json=payload).json()


ERROR_CODES = {
    "0": "Success",
    "-1010": "Invalid Public Key Length",
    "-1012": "Invalid terminalUUID",
    "-1501": "Invalid Request or Credentials",
    "1002": "Incorrect Request",
    "-1003": "JSON formatting error",
    "-1008": "Invalid value",
}
COOKIE_NAME = "TP_SESSIONID"


class P100():
    """Control Tapo P100 sockets."""

    def __init__(self, ip_address, email, password):
        """Initialize the class."""
        self.ip_address = ip_address
        self._terminal_uuid = str(uuid.uuid4())
        self._session = Session()
        self._email = None
        self._password = None
        self._private_key = None
        self._public_key = None
        self._headers = None
        self._token = None
        self._tplink_cipher = None
        self._error_codes = ERROR_CODES

        self._encrypt_credentials(email, password)
        self._create_key_pair()
        self._handshake()
        self._login()

    def _encrypt_credentials(self, email, password):
        """Encrypt credentials."""
        self._password = tp_link_cipher.TpLinkCipher.mime_encoder(password.encode("utf-8"))
        encoded_email = sha_digest(email)
        self._email = tp_link_cipher.TpLinkCipher.mime_encoder(encoded_email.encode("utf-8"))

    def _create_key_pair(self):
        """Create private and public keys."""
        keys = RSA.generate(1024)

        self._private_key = keys.exportKey("PEM")
        self._public_key = keys.public_key().exportKey("PEM")

    def _decode_handshake_key(self, key):
        """Decode handshake."""
        decoded_key: bytes = b64decode(key.encode("UTF-8"))
        decoded_private_key: bytes = self._private_key

        cipher = PKCS1_v1_5.new(RSA.importKey(decoded_private_key))
        decrypted_key = cipher.decrypt(decoded_key, None)
        if decrypted_key is None:
            raise ValueError("Decryption failed!")

        return tp_link_cipher.TpLinkCipher(decrypted_key[:16], decrypted_key[16:])

    def _handshake(self):
        """Handle handshake with the device."""
        url = f"http://{self.ip_address}/app"
        payload = self._get_handshake_payload()

        r = self._session.post(url, json=payload, timeout=2)

        encrypted_key = r.json()["result"]["key"]
        self._tplink_cipher = self._decode_handshake_key(encrypted_key)

        try:
            self._headers = {
                "Cookie": f"{COOKIE_NAME}={r.cookies[COOKIE_NAME]}"
            }
        except Exception:
            error_code = r.json()["error_code"]
            error_message = self._error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")

    def _get_handshake_payload(self):
        return {
            "method": "handshake",
            "params": {
                "key": self._public_key.decode("utf-8"),
                "requestTimeMils": int(round(time.time() * 1000))
            }
        }

    def _login(self):
        """Handle login with the device."""
        url = f"http://{self.ip_address}/app"
        payload = self._get_secure_payload(
            self._get_login_payload()
        )

        try:
            response = self._get_response(url, payload)
            self._token = ast.literal_eval(response)["result"]["token"]
        except Exception:
            self._log_error(response)
            raise

    def _get_secure_payload(self, payload):
        return {
            "method": "securePassthrough",
            "params": {
                "request": self._tplink_cipher.encrypt(json.dumps(payload))
            }
        }

    def _get_login_payload(self):
        return {
            "method": "login_device",
            "params": {
                "username": self._email,
                "password": self._password
            },
            "requestTimeMils": int(round(time.time() * 1000)),
        }

    def _get_response(self, url, payload):
        response = self._session.post(url, json=payload, headers=self._headers, timeout=2)
        return self._tplink_cipher.decrypt(response.json()["result"]["response"])

    def turn_on(self):
        """Power on the device."""
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"device_on": True})
        )

        try:
            response = self._get_response(url, payload)
        finally:
            self._log_errors(response)

    def _log_errors(self, response):
        if ast.literal_eval(response)["error_code"] != 0:
            error_code = ast.literal_eval(response)["error_code"]
            error_message = self._error_codes[str(error_code)]
            LOGGER.error(f"Error code: {error_code}, {error_message}")

    def _get_set_device_info_payload(self, params=None):
        return {
            "method": "set_device_info",
            "params": params,
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self._terminal_uuid
        }

    def turn_off(self):
        """Power off the device."""
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"device_on": False})
        )

        try:
            response = self._get_response(url, payload)
        finally:
            self._log_errors(response)

    def toggle_power(self):
        """Toggle device on/off."""
        if self.get_device_info()["result"]["device_on"]:
            self.turn_off()
        else:
            self.turn_on()

    def get_device_info(self):
        """Retrieve current settings from the device."""
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            _get_device_info_payload()
        )

        response = self._get_response(url, payload)

        return json.loads(response)

    def get_device_name(self):
        """Get the device name."""
        data = self.get_device_info()

        if data["error_code"] != 0:
            error_code = ast.literal_eval(data)["error_code"]
            error_message = self._error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")
        else:
            encoded_name = data["result"]["nickname"]
            name = b64decode(encoded_name)
            return name.decode("utf-8")

    def turn_on_with_delay(self, delay):
        """Switch on the device with a time delay."""
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_add_countdown_rule_payload(delay, True)
        )

        try:
            response = self._get_response(url, payload)
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
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = self._get_secure_payload(
            self._get_add_countdown_rule_payload(delay, False)
        )

        try:
            response = self._get_response(url, payload)
        finally:
            self._log_errors(response)


def sha_digest(data):
    """Digest string SHA."""
    b_arr = data.encode("UTF-8")
    digest = hashlib.sha1(b_arr).digest()

    sb = ""
    for i in range(0, len(digest)):
        b = digest[i]
        hex_string = hex(b & 255).replace("0x", "")
        if len(hex_string) == 1:
            sb += "0"
            sb += hex_string
        else:
            sb += hex_string

    return sb


def _get_device_info_payload():
    return {
        "method": "get_device_info",
        "requestTimeMils": int(round(time.time() * 1000)),
    }
