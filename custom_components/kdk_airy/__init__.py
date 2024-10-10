"""Custom integration to integrate KDK Airy with Home Assistant.

For more details about this integration, please refer to
https://github.com/gabrielsim/kdk_airy
"""

from __future__ import annotations

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.loader import async_get_loaded_integration

from .api import KdkApiClient
from .coordinator import KdkAiryDataUpdateCoordinator
from .data import KdkConfigEntry, KdkData

PLATFORMS: list[Platform] = [
    Platform.FAN,
    Platform.LIGHT,
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
) -> bool:
    """Set up this integration using UI."""

    client = KdkApiClient(
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        session=async_get_clientsession(hass),
    )
    coordinator = KdkAiryDataUpdateCoordinator(hass=hass, api=client)
    await client.login()
    entry.runtime_data = KdkData(
        client=client,
        coordinator=coordinator,
        integration=async_get_loaded_integration(hass, entry.domain),
    )
    await coordinator.async_config_entry_first_refresh()

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_reload_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
