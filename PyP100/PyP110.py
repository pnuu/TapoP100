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
        url = f"http://{self.ip_address}/app?token={self._token}"
        payload = {
            "method": "get_energy_usage",
            "requestTimeMils": int(round(time.time() * 1000)),
        }
        payload = {
            "method": "securePassthrough",
            "params": {
                "request": self._tplink_cipher.encrypt(json.dumps(payload))
            }
        }
        _LOGGER.debug("getEnergyUsage %s", self.ip_address)

        response = self._get_response(url, payload)

        return json.loads(response)
