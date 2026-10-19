"""DataUpdateCoordinator for KDK Airy."""

from __future__ import annotations

from datetime import datetime, timedelta

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import InvalidAuth, KdkDevice
from .client import KdkHybridClient
from .const import DOMAIN, LOGGER


class KdkAiryDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the API."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: KdkHybridClient,
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
        try:
            self._devices = await self._api.get_registered_fans()
        except InvalidAuth as exception:
            raise ConfigEntryAuthFailed(exception) from exception
        except Exception as exception:
            # retried by HA as ConfigEntryNotReady
            raise UpdateFailed(exception) from exception

    async def _async_update_data(self):
        """Update data via library."""
        try:
            start_time = datetime.now().timestamp()
            LOGGER.debug(f"Polling for updates from {len(self._devices)} fans")
            statuses = await self._api.get_statuses(devices=self._devices)
            # a local poll costs ~200 ms with no cloud load; poll faster when
            # every fan answered on the LAN
            self.update_interval = timedelta(seconds=5 if self._api.all_local else 15)
            if self._api.cloud_auth_failed and self.config_entry:
                # the local fans still answered, so keep polling them
                self.config_entry.async_start_reauth(self.hass)
            return statuses | {"polled_time": start_time}
        except InvalidAuth as exception:
            LOGGER.warning(f"Authentication failed: {exception}")
            raise ConfigEntryAuthFailed(exception) from exception
        except Exception as exception:
            LOGGER.error(f"Unexpected error during update: {exception}")
            raise UpdateFailed(exception) from exception
