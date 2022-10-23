"""Utility functions."""

import time

from requests.exceptions import ConnectTimeout

RETRIES = 5


def get_response_with_retries(session, url, payload, headers=None):
    for _ in range(RETRIES):
        try:
            response = session.post(url, json=payload, headers=headers, timeout=2)
            return response
        except ConnectTimeout:
            time.sleep(0.1)


def get_set_device_info_payload(terminal_uuid, params=None):
    return {
        "method": "set_device_info",
        "params": params,
        "requestTimeMils": int(round(time.time() * 1000)),
        "terminalUUID": terminal_uuid
    }
