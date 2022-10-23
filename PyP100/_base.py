"""Base module for TP-Link Tapo devices."""

import ast
from base64 import b64decode
import hashlib
import json
import time
import uuid

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from requests import Session
from requests.exceptions import ConnectTimeout

from PyP100 import tp_link_cipher

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
RETRIES = 5


class TapoBase:
    """Base class for TP-Link Tapo devices."""

    def __init__(self, ip_address, email, password):
        """Initialize the class."""
        self.ip_address = ip_address
        self._app_url = f"http://{self.ip_address}/app"
        self._authenticated_url = None
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
        self._set_authenticated_url()

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
        payload = self._get_handshake_payload()

        response = _get_response_with_retries(self._session, self._app_url, payload)
        encrypted_key = response.json()["result"]["key"]
        self._tplink_cipher = self._decode_handshake_key(encrypted_key)

        try:
            self._headers = {
                "Cookie": f"{COOKIE_NAME}={response.cookies[COOKIE_NAME]}"
            }
        except Exception:
            error_code = response.json()["error_code"]
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
        payload = self._get_secure_payload(
            self._get_login_payload()
        )

        try:
            response = self._get_response(self._app_url, payload)
            self._token = ast.literal_eval(response)["result"]["token"]
        except Exception:
            self._log_errors(response)
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
        response = _get_response_with_retries(self._session, url, payload, headers=self._headers)
        return self._tplink_cipher.decrypt(response.json()["result"]["response"])

    def _set_authenticated_url(self):
        self._authenticated_url = f"http://{self.ip_address}/app?token={self._token}"

    def turn_on(self):
        """Power on the device."""
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"device_on": True})
        )

        try:
            response = self._get_response(self._authenticated_url, payload)
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
        payload = self._get_secure_payload(
            self._get_set_device_info_payload(params={"device_on": False})
        )

        try:
            response = self._get_response(self._authenticated_url, payload)
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
        payload = self._get_secure_payload(
            _get_device_info_payload()
        )

        response = self._get_response(self._authenticated_url, payload)

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
        payload = self._get_secure_payload(
            self._get_add_countdown_rule_payload(delay, True)
        )

        try:
            response = self._get_response(self._authenticated_url, payload)
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
            response = self._get_response(self._authenticated_url, payload)
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


def _get_response_with_retries(session, url, payload, headers=None):
    for _ in range(RETRIES):
        try:
            response = session.post(url, json=payload, headers=headers, timeout=2)
            return response
        except ConnectTimeout:
            time.sleep(0.1)
