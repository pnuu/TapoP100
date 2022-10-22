"""Module for handling Tapo P100 sockets."""

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
    "-1003": "JSON formatting error "
}


class P100():
    """Control Tapo P100 sockets."""

    def __init__(self, ip_address, email, password):
        """Initialize the class."""
        self.ip_address = ip_address
        self.terminal_uuid = str(uuid.uuid4())

        self.email = email
        self.password = password
        self.session = Session()
        self.cookie_name = "TP_SESSIONID"

        self.error_codes = ERROR_CODES

        self.encrypt_credentials(email, password)
        self.create_key_pair()

    def encrypt_credentials(self, email, password):
        """Encrypt credentials."""
        # Password Encoding
        self.encoded_password = tp_link_cipher.TpLinkCipher.mime_encoder(password.encode("utf-8"))

        # Email Encoding
        self.encoded_email = self.sha_digest_username(email)
        self.encoded_email = tp_link_cipher.TpLinkCipher.mime_encoder(self.encoded_email.encode("utf-8"))

    def create_key_pair(self):
        """Create private and public keys."""
        self.keys = RSA.generate(1024)

        self.private_key = self.keys.exportKey("PEM")
        self.public_key = self.keys.public_key().exportKey("PEM")

    def decode_handshake_key(self, key):
        """Decode handshake."""
        decode: bytes = b64decode(key.encode("UTF-8"))
        decode2: bytes = self.private_key

        cipher = PKCS1_v1_5.new(RSA.importKey(decode2))
        do_final = cipher.decrypt(decode, None)
        if do_final is None:
            raise ValueError("Decryption failed!")

        b_arr: bytearray = bytearray()
        b_arr2: bytearray = bytearray()

        for i in range(0, 16):
            b_arr.insert(i, do_final[i])
        for i in range(0, 16):
            b_arr2.insert(i, do_final[i + 16])

        return tp_link_cipher.TpLinkCipher(b_arr, b_arr2)

    def sha_digest_username(self, data):
        """Digest username SHA."""
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

    def handshake(self):
        """Handle handshake with the device."""
        url = f"http://{self.ip_address}/app"
        payload = {
            "method": "handshake",
            "params": {
                "key": self.public_key.decode("utf-8"),
                "requestTimeMils": int(round(time.time() * 1000))
            }
        }

        r = self.session.post(url, json=payload, timeout=2)

        encrypted_key = r.json()["result"]["key"]
        self.tplink_cipher = self.decode_handshake_key(encrypted_key)

        try:
            self.cookie = f"{self.cookie_name}={r.cookies[self.cookie_name]}"

        except Exception:
            error_code = r.json()["error_code"]
            error_message = self.error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")

    def login(self):
        """Handle login with the device."""
        url = f"http://{self.ip_address}/app"
        payload = {
            "method": "login_device",
            "params": {
                "username": self.encoded_email,
                "password": self.encoded_password
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

        try:
            self.token = ast.literal_eval(decrypted_response)["result"]["token"]
        except Exception:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")

    def turn_on(self):
        """Power on the device."""
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "set_device_info",
            "params": {
                "device_on": True
            },
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid
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

    def turn_off(self):
        """Power off the device."""
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "set_device_info",
            "params": {
                "device_on": False
            },
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": self.terminal_uuid
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

    def get_device_info(self):
        """Retrieve current settings from the device."""
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "get_device_info",
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

        r = self.session.post(url, json=secure_passthrough_payload, headers=headers)
        decrypted_response = self.tplink_cipher.decrypt(r.json()["result"]["response"])

        return json.loads(decrypted_response)

    def get_device_name(self):
        """Get the device name."""
        self.handshake()
        self.login()
        data = self.get_device_info()

        if data["error_code"] != 0:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")
        else:
            encoded_name = data["result"]["nickname"]
            name = b64decode(encoded_name)
            return name.decode("utf-8")

    def turn_on_with_delay(self, delay):
        """Switch on the device with a time delay."""
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "add_countdown_rule",
            "params": {
                "delay": int(delay),
                "desired_states": {
                    "on": True
                },
                "enable": True,
                "remain": int(delay)
            },
            "terminalUUID": self.terminal_uuid
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

        r = self.session.post(url, json=secure_passthrough_payload, headers=headers)

        decrypted_response = self.tplink_cipher.decrypt(r.json()["result"]["response"])

        if ast.literal_eval(decrypted_response)["error_code"] != 0:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")

    def turn_off_with_delay(self, delay):
        """Switch off the device with a time delay."""
        url = f"http://{self.ip_address}/app?token={self.token}"
        payload = {
            "method": "add_countdown_rule",
            "params": {
                "delay": int(delay),
                "desired_states": {
                    "on": False
                },
                "enable": True,
                "remain": int(delay)
            },
            "terminalUUID": self.terminal_uuid
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

        r = self.session.post(url, json=secure_passthrough_payload, headers=headers)

        decrypted_response = self.tplink_cipher.decrypt(r.json()["result"]["response"])

        if ast.literal_eval(decrypted_response)["error_code"] != 0:
            error_code = ast.literal_eval(decrypted_response)["error_code"]
            error_message = self.error_codes[str(error_code)]
            raise Exception(f"Error Code: {error_code}, {error_message}")
