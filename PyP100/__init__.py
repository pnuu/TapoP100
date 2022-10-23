"""Package for TP-Link Tapo devices."""

import ast
import hashlib
import logging
import time
from base64 import b64decode, b64encode

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from PyP100 import tp_link_cipher
from PyP100._base import ERROR_CODES, TapoCommunication
from PyP100.l530 import L530
from PyP100.p100 import P100
from PyP100.p110 import P110
from PyP100.utils import get_response_with_retries

COOKIE_NAME = "TP_SESSIONID"
DEVICES = {
    'P100': P100,
    'P110': P110,
    'L510': L530,
    'L530': L530,
}
LOGGER = logging.getLogger()


class Tapo(TapoCommunication):
    """Utility class for creating device control objects."""

    def __init__(self, ip_address, email, password):
        """Initialize the class."""
        self.ip_address = ip_address
        self._app_url = f"http://{self.ip_address}/app"
        self._handshake()
        self._login(email, password)

    def _handshake(self):
        """Handle handshake with the device."""
        private_key, public_key = _create_key_pair()
        payload = _get_handshake_payload(public_key)
        response = get_response_with_retries(self._session, self._app_url, payload)
        self._tplink_cipher = _decode_handshake_key(response.json()["result"]["key"], private_key)
        self._headers = _get_headers(response)

    def _login(self, email, password):
        """Handle login with the device."""
        email, password = _get_encrypted_credentials(email, password)
        payload = self._get_secure_payload(
            _get_login_payload(email, password)
        )
        try:
            response = self._get_response(self._app_url, payload)
            self._token = ast.literal_eval(response)["result"]["token"]
        except Exception:
            self._log_errors(response)
            raise

    def get_device(self):
        """Create device instance."""
        info = self.get_device_info()
        device = info['result']['model']
        LOGGER.info(f"{device} initialized.")
        return DEVICES[device](self.ip_address, self._token, self._tplink_cipher)


def _create_key_pair():
    """Create private and public keys."""
    keys = RSA.generate(1024)

    private_key = keys.exportKey("PEM")
    public_key = keys.public_key().exportKey("PEM")

    return private_key, public_key


def _decode_handshake_key(key, private_key):
    """Decode handshake."""
    decoded_key: bytes = b64decode(key.encode("UTF-8"))

    cipher = PKCS1_v1_5.new(RSA.importKey(private_key))
    decrypted_key = cipher.decrypt(decoded_key, None)
    if decrypted_key is None:
        raise ValueError("Decryption failed!")

    return tp_link_cipher.TpLinkCipher(decrypted_key[:16], decrypted_key[16:])


def _get_headers(response):
    try:
        return {
            "Cookie": f"{COOKIE_NAME}={response.cookies[COOKIE_NAME]}"
        }
    except Exception:
        error_code = response.json()["error_code"]
        error_message = ERROR_CODES[str(error_code)]
        raise Exception(f"Error Code: {error_code}, {error_message}")


def _get_handshake_payload(public_key):
    return {
        "method": "handshake",
        "params": {
            "key": public_key.decode("utf-8"),
            "requestTimeMils": int(round(time.time() * 1000))
        }
    }


def _get_encrypted_credentials(email, password):
    """Encrypt credentials."""
    password = b64encode(password.encode("utf-8")).decode("UTF-8")
    encoded_email = sha_digest(email)
    email = b64encode(encoded_email.encode("utf-8")).decode("UTF-8")

    return email, password


def _get_login_payload(email, password):
    return {
        "method": "login_device",
        "params": {
            "username": email,
            "password": password
        },
        "requestTimeMils": int(round(time.time() * 1000)),
    }


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
