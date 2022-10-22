"""Module for handling Tapo P110 power monitoring sockets."""

from PyP100 import PyP100

import json
import logging
import time

_LOGGER = logging.getLogger(__name__)


class P110(PyP100.P100):
    """Control Tapo P110 sockets."""

    def get_energy_usage(self):
        """Get the energy usage from the device."""
        URL = f"http://{self.ip_address}/app?token={self._token}"
        payload = {
            "method": "get_energy_usage",
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self._cookie
        }

        encrypted_payload = self._tplink_cipher.encrypt(json.dumps(payload))

        secure_passthrough_payload = {
            "method": "securePassthrough",
            "params": {
                "request": encrypted_payload
            }
        }
        _LOGGER.debug("getEnergyUsage %s", self.ip_address)
        r = self._session.post(URL, json=secure_passthrough_payload, headers=headers, timeout=2)

        decrypted_response = self._tplink_cipher.decrypt(r.json()["result"]["response"])

        return json.loads(decrypted_response)
