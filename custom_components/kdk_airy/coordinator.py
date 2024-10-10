"""DataUpdateCoordinator for KDK Airy."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AuthExpired, KdkApiClient, KdkDevice
from .const import DOMAIN, LOGGER


class KdkAiryDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: KdkApiClient,
    ) -> None:
        """Initialize."""
        super().__init__(
            hass=hass,
            logger=LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=15),
        )
        self._api = api
        self._devices: list[KdkDevice] = []

    async def _async_setup(self):
        "Save the list of registered fans to be polled."
        self._devices = await self._api.get_registered_fans()

    async def _async_update_data(self):
        """Update data via library."""
        try:
            LOGGER.debug(f"Polling for updates from {len(self._devices)} fans")
            return await self._api.get_statuses(devices=self._devices)
        except AuthExpired as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except Exception as exception:
            raise UpdateFailed(exception) from exception
