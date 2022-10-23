"""Module for handling Tapo P100 sockets."""

import logging

from PyP100._base import TapoBase

LOGGER = logging.getLogger(__name__)


class P100(TapoBase):
    """Control Tapo P100 sockets."""
