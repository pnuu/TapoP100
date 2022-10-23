"""Module for handling the TP-Link cipher."""

import base64

import pkcs7
from Crypto.Cipher import AES


class TpLinkCipher:
    """TP-Link cipher handling."""

    def __init__(self, key: bytearray, iv_: bytearray):
        """Initialize the class."""
        self.key = key
        self.iv = iv_

    def encrypt(self, data):
        """Encrypt the data."""
        data = pkcs7.PKCS7Encoder().encode(data)
        cipher = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
        encrypted = cipher.encrypt(data.encode("UTF-8"))
        return base64.b64encode(encrypted).decode("UTF-8")

    def decrypt(self, data: str):
        """Decrypt the data."""
        aes = AES.new(bytes(self.key), AES.MODE_CBC, bytes(self.iv))
        pad_text = aes.decrypt(base64.b64decode(data.encode("UTF-8"))).decode("UTF-8")
        return pkcs7.PKCS7Encoder().decode(pad_text)
