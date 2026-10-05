"""Local-first KDK client with cloud fallback.

Exposes the same calls as KdkApiClient, so the coordinator and entities don't
care which path a device takes. Routing mirrors the official app: the cloud
supplies the device list, a LAN broadcast maps each device's hashed_guid to an
IP, and any device not reachable on the LAN goes through the cloud.
"""

from __future__ import annotations

import asyncio
import time

from .api import (
    AuthExpired,
    CommandInvalid,
    KdkApiClient,
    KdkDevice,
    KdkDeviceSettings,
    RefreshTokenExpired,
)
from .const import LOGGER
from .local import (
    ESV_GET,
    ESV_GET_RES,
    ESV_GET_SNA,
    ESV_SET_RES,
    ESV_SETC,
    LocalTransport,
    async_discover,
    props_to_cloud_packet,
    settings_to_props,
    status_props,
)

# Fans are on DHCP, so addresses are rediscovered rather than remembered.
REDISCOVER_UNMAPPED = 60  # a registered fan hasn't been found on the LAN yet
REDISCOVER_AFTER_FAILURE = 10  # a local request just went unanswered
REDISCOVER_PERIODIC = 600
MAX_MISSES = 3  # consecutive unanswered polls before a fan is treated as moved
STATUS_TIMEOUT = 3.0  # how long one fan's status read may take, busy spells included
BUSY_RETRY = 0.3  # wait between reads while a fan is still busy with a command


class KdkHybridClient:
    "KDK client that talks to fans on the LAN when it can and the cloud when it can't."

    def __init__(self, cloud: KdkApiClient) -> None:
        "Wrap a cloud client."
        self._cloud = cloud
        self._local: LocalTransport | None = None
        self._broadcast: list[str] = []
        self._devices: list[KdkDevice] | None = None
        self._ips: dict[str, str] = {}  # hashed_guid -> ip
        self._misses: dict[str, int] = {}
        self._last_discovery = 0.0
        self._discovery_task: asyncio.Task | None = None
        self._all_local = False

    @property
    def all_local(self) -> bool:
        "Whether the last poll reached every fan on the LAN."
        return self._all_local

    async def async_start(self, broadcast_addrs: list[str]) -> None:
        "Bind the local socket and find the fans. Falls back to cloud-only on failure."
        self._broadcast = list(broadcast_addrs)
        try:
            self._local = await LocalTransport.create()
        except OSError as err:
            LOGGER.warning(
                "Local control disabled, using the cloud only: could not bind UDP "
                f"3610 ({err}). Another process on this host (e.g. an ECHONET Lite "
                "integration) is probably holding it"
            )
            return
        if not self._broadcast:
            LOGGER.warning(
                "Local control disabled, using the cloud only: no IPv4 network "
                "adapter is enabled in Home Assistant's network settings"
            )
            return
        # Known devices let the first search report how many fans it found.
        await self.get_registered_fans()
        await self._async_discover()

    async def async_stop(self) -> None:
        "Release UDP 3610 so a reload can bind it again."
        if self._discovery_task is not None:
            self._discovery_task.cancel()
            self._discovery_task = None
        if self._local is not None:
            self._local.close()
            self._local = None

    async def login(self, force_new_login: bool = False):
        "Log in to the cloud, which still supplies the device list and the fallback."
        return await self._cloud.login(force_new_login=force_new_login)

    async def get_registered_fans(self) -> list[KdkDevice]:
        "Return the account's fans, fetched from the cloud once."
        if self._devices is None:
            self._devices = await self._cloud.get_registered_fans()
        return self._devices

    # ---------------------------------------------------------------- discovery

    async def _async_discover(self) -> None:
        if self._local is None or not self._broadcast:
            return
        self._last_discovery = time.monotonic()
        try:
            found = await async_discover(self._broadcast)
        except OSError as err:
            LOGGER.debug(f"Local discovery failed: {err}")
            return

        for guid, ip in found.items():
            if self._ips.get(guid) != ip:
                LOGGER.debug(f"Fan {guid[:12]} found at {ip}")
            self._ips[guid] = ip
            self._misses.pop(guid, None)

        if self._devices is not None:
            local = sum(1 for d in self._devices if d.hashed_guid in self._ips)
            LOGGER.debug(
                f"{local} of {len(self._devices)} fans reachable locally "
                f"(searched {', '.join(self._broadcast)})"
            )

    def _schedule_discovery(self, min_age: float) -> None:
        "Rediscover in the background, unless one ran recently or is running."
        if self._local is None:
            return
        if self._discovery_task is not None and not self._discovery_task.done():
            return
        if time.monotonic() - self._last_discovery < min_age:
            return
        self._discovery_task = asyncio.create_task(self._async_discover())

    def _record_miss(self, device: KdkDevice) -> None:
        guid = device.hashed_guid
        self._misses[guid] = self._misses.get(guid, 0) + 1
        if self._misses[guid] >= MAX_MISSES and guid in self._ips:
            LOGGER.debug(
                f"{device.name} unanswered {MAX_MISSES} times locally, using the cloud"
            )
            del self._ips[guid]
            self._misses.pop(guid, None)
        self._schedule_discovery(REDISCOVER_AFTER_FAILURE)

    # ------------------------------------------------------------------ polling

    async def get_statuses(
        self, devices: list[KdkDevice]
    ) -> dict[str, KdkDeviceSettings]:
        "Get every device's state, locally where possible, as {appliance_id: settings}."
        if self._local is None:
            return await self._cloud.get_statuses(devices) if devices else {}

        if any(d.hashed_guid not in self._ips for d in devices):
            self._schedule_discovery(REDISCOVER_UNMAPPED)
        else:
            self._schedule_discovery(REDISCOVER_PERIODIC)

        local = [d for d in devices if d.hashed_guid in self._ips]
        results = await asyncio.gather(
            *(self._async_local_status(d) for d in local), return_exceptions=True
        )

        statuses: dict[str, KdkDeviceSettings] = {}
        cloud = [d for d in devices if d.hashed_guid not in self._ips]
        for device, result in zip(local, results):
            if isinstance(result, BaseException):
                # One dropped packet shouldn't make a fan unavailable: ask the
                # cloud this time, and only stop trying locally after repeats.
                LOGGER.debug(f"No local status from {device.name}: {result!r}")
                self._record_miss(device)
                cloud.append(device)
                continue
            self._misses.pop(device.hashed_guid, None)
            statuses[device.appliance_id] = KdkDeviceSettings.parse_data_packet(
                packet=props_to_cloud_packet(result)
            )

        self._all_local = bool(devices) and not cloud
        if not cloud:
            return statuses
        if not local:
            # cloud-only this cycle: fail exactly as before local support existed
            return statuses | await self._cloud.get_statuses(cloud)
        try:
            return statuses | await self._cloud.get_statuses(cloud)
        except (AuthExpired, RefreshTokenExpired):
            raise  # still needs reauth
        except Exception as err:  # noqa: BLE001
            # The local fans are fine; don't fail the whole update for the rest.
            LOGGER.warning(f"Cloud fallback failed for {len(cloud)} fan(s): {err}")
            return statuses

    async def _async_local_status(self, device: KdkDevice) -> list:
        """Read one fan's status properties, waiting out a busy spell.

        For about a second after it accepts a command, a fan answers status
        reads with Get_SNA and every property empty (measured on an E48GP).
        That means "busy", not "unknown": publishing it would blank the fan's
        and light's state in HA, and make "turn on at last setting" fall back to
        defaults. So read again until real values come back. A Get_SNA that does
        carry data is a genuine partial reply and is used as is.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + STATUS_TIMEOUT
        ip = self._ips[device.hashed_guid]
        wanted = status_props(device.has_lights)
        while True:
            esv, props = await self._local.request(
                ip, ESV_GET, wanted, timeout=max(0.1, deadline - loop.time())
            )
            if esv == ESV_GET_RES or (
                esv == ESV_GET_SNA and any(edt for _, edt in props)
            ):
                return props
            if loop.time() + BUSY_RETRY >= deadline:
                raise TimeoutError(
                    f"{device.name} still busy after {STATUS_TIMEOUT:.0f}s "
                    f"(ESV {esv:02X}, no property values)"
                )
            await asyncio.sleep(BUSY_RETRY)

    # ----------------------------------------------------------------- commands

    async def change_settings(
        self, appliance_id: str, desired_setting: KdkDeviceSettings
    ) -> None:
        "Apply settings, locally if the fan is reachable, else through the cloud."
        device = next(
            (d for d in self._devices or [] if d.appliance_id == appliance_id), None
        )
        ip = self._ips.get(device.hashed_guid) if device else None

        if self._local is not None and ip is not None:
            props = settings_to_props(desired_setting)
            try:
                esv, reply = await self._local.request(ip, ESV_SETC, props)
            except (TimeoutError, ConnectionError, OSError) as err:
                LOGGER.warning(
                    f"{device.name} didn't answer locally ({err}), using the cloud"
                )
                self._record_miss(device)
            else:
                if esv == ESV_SET_RES:
                    LOGGER.debug(f"{device.name} set locally: {desired_setting}")
                    return
                # SetC_SNA isn't all-or-nothing: the accepted properties have
                # already applied. Retrying via the cloud would be refused too.
                refused = [f"{epc:02X}" for epc, edt in reply if edt]
                raise CommandInvalid(
                    f"{device.name} refused {', '.join(refused) or 'the command'} "
                    f"(ESV {esv:02X})"
                )

        await self._cloud.change_settings(
            appliance_id=appliance_id, desired_setting=desired_setting
        )
