"""Custom integration to integrate KDK Airy with Home Assistant.

For more details about this integration, please refer to
https://github.com/gabrielsim/kdk_airy
"""

from __future__ import annotations

from homeassistant.components import network
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.loader import async_get_loaded_integration

from .api import KdkApiClient
from .client import KdkHybridClient
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

    client = KdkHybridClient(
        KdkApiClient(
            username=entry.data[CONF_USERNAME],
            password=entry.data[CONF_PASSWORD],
            session=async_get_clientsession(hass),
        )
    )
    coordinator = KdkAiryDataUpdateCoordinator(hass=hass, api=client)
    await client.login()

    broadcast_addrs = await network.async_get_ipv4_broadcast_addresses(hass)
    await client.async_start([str(addr) for addr in broadcast_addrs])
    try:
        entry.runtime_data = KdkData(
            client=client,
            coordinator=coordinator,
            integration=async_get_loaded_integration(hass, entry.domain),
        )
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        # HA retries a failed setup; UDP 3610 must be free for that retry
        await client.async_stop()
        raise

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
) -> bool:
    """Handle removal of an entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        # a reload sets up a new client, which needs UDP 3610 released
        await entry.runtime_data.client.async_stop()
    return unloaded


async def async_reload_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
) -> None:
    """Reload config entry."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
