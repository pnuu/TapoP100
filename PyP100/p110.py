"""Module for handling Tapo P110 power monitoring sockets."""

import json
import logging
import time

from PyP100._base import TapoBase

LOGGER = logging.getLogger(__name__)


class P110(TapoBase):
    """Control Tapo P110 sockets."""

    def get_energy_usage(self):
        """Get the energy usage from the device."""
        payload = self._get_secure_payload(
            _get_energy_usage_payload()
        )
        LOGGER.debug("getEnergyUsage %s", self.ip_address)

        try:
            response = self._get_response(f"http://{self.ip_address}/app?token={self._token}", payload)
        finally:
            self._log_errors(response)

        return json.loads(response)


def _get_energy_usage_payload():
    return {
        "method": "get_energy_usage",
        "requestTimeMils": int(round(time.time() * 1000)),
    }
