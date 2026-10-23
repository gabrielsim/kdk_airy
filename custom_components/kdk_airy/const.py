"""Constants for KDK Airy."""

from logging import Logger, getLogger

LOGGER: Logger = getLogger(__package__)

DOMAIN = "kdk_airy"

MIN_KELVIN = 3000  # Warmest temperature, API = 0%
MAX_KELVIN = 7000  # Coolest temperature, API = 100%
DEFAULT_KELVIN = 6000  # Cloudy
