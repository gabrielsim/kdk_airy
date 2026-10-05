"""Local (LAN) control of KDK fans over ECHONET Lite.

The fans speak unauthenticated ECHONET Lite on UDP 3610 and are found by an
SSDP-style M-SEARCH broadcast on UDP 50125 - the same path the official app uses
whenever the phone is on the fans' network. Everything here was measured against
real E48GP / E48HP fans rather than inferred.

Deliberately free of Home Assistant and aiohttp imports, so it can be exercised
on its own against real hardware.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import struct

from .const import LOGGER

EL_PORT = 3610
SSDP_PORT = 50125

SEOJ = bytes([0x05, 0xFF, 0x01])  # controller
DEOJ = bytes([0x01, 0x3A, 0x01])  # KDK ceiling fan object

ESV_SETC = 0x61
ESV_GET = 0x62
ESV_SET_RES = 0x71
ESV_GET_RES = 0x72
ESV_SETC_SNA = 0x51
ESV_GET_SNA = 0x52

# What's worth polling: power, speed, direction, fluctuation, and the light
# block on models that have one. Timers and error codes never change and cost
# ~15 ms each per poll.
FAN_EPCS = (0x80, 0xF0, 0xF1, 0xF2)
LIGHT_EPCS = (0xF3, 0xF4, 0xF5, 0xF6, 0xF7)

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST:{host}:%d\r\n"
    'MAN:"ssdp:discover"\r\n'
    "MX:3\r\n"
    "ST:urn:schemas-upnp-org:device:PANA013Adevices:1\r\n"
    "\r\n" % SSDP_PORT
)

# HASHGUID, COMMID and PARTID use '=' where the other headers use ':'
_SSDP_HEADER = re.compile(r"([A-Za-z-]+)\s*[:=]\s*(.*)$")

Props = list[tuple[int, bytes]]


def build_frame(tid: int, esv: int, props: Props) -> bytes:
    """Build an ECHONET Lite frame for the fan object."""
    body = b"".join(bytes([epc, len(edt)]) + edt for epc, edt in props)
    return (
        b"\x10\x81"
        + struct.pack(">H", tid)
        + SEOJ
        + DEOJ
        + bytes([esv, len(props)])
        + body
    )


def parse_frame(data: bytes) -> tuple[int, int, Props]:
    """Parse an ECHONET Lite frame into (tid, esv, [(epc, edt), ...])."""
    if len(data) < 12 or data[0:2] != b"\x10\x81":
        raise ValueError(f"not an ECHONET Lite frame: {data.hex()}")
    tid = struct.unpack(">H", data[2:4])[0]
    esv, opc = data[10], data[11]
    props, i = [], 12
    for _ in range(opc):
        if i + 1 >= len(data):
            break
        epc, pdc = data[i], data[i + 1]
        props.append((epc, data[i + 2 : i + 2 + pdc]))
        i += 2 + pdc
    return tid, esv, props


def props_to_cloud_packet(props: Props) -> str:
    """Render local properties in the cloud's packet format.

    The cloud wraps the same ECHONET Lite properties with a leading 00 on every
    EPC, so a local reply converted this way decodes through
    KdkDeviceSettings.parse_data_packet exactly as a cloud reply does.
    """
    entries = "".join(
        f"00{epc:02X}{len(edt):02X}{edt.hex().upper()}" for epc, edt in props
    )
    return f"{len(props):02X}{entries}"


def status_props(has_lights: bool) -> Props:
    """Properties to ask for in a status Get."""
    epcs = FAN_EPCS + (LIGHT_EPCS if has_lights else ())
    return [(epc, b"") for epc in epcs]


def settings_to_props(settings) -> Props:
    """Build a local SetC from a KdkDeviceSettings.

    Only frame shapes measured as accepted are produced:
      fan    off: 80=31              on: 80=30 F0 F1 F2=31
      light  off: F3=31  day: F3=30 F4=42 F5 F6  night: F3=30 F4=43 F7
    A fan property is refused unless 0x80 is in the frame. A light property is
    refused unless 0xF3 is in the frame *and on*, and each light mode only
    accepts its own properties (F5/F6 in day, F7 in night) with 0xF4 present.

    Unlike the cloud packet this omits 0x93 (the app strips it on the local
    path) and the 0xF8 off-timer (never exercised locally).
    """
    props: Props = [
        (0xFD, b"\x03"),  # control source: in-house app
        (0xFC, b"\x30"),  # buzzer on, as the cloud packet does
        (0xFE, b"\x40"),  # no melody
    ]

    if settings.fan_power is False:
        props.append((0x80, b"\x31"))
    elif settings.fan_power:
        props.append((0x80, b"\x30"))
        if settings.fan_volume is not None:
            speed = min(10, max(1, int(settings.fan_volume / 10)))
            props.append((0xF0, bytes([0x30 + speed])))
        if settings.fan_direction is not None:
            props.append(
                (0xF1, {"forward": b"\x41", "reverse": b"\x42"}[settings.fan_direction])
            )
        props.append((0xF2, b"\x31"))  # fluctuation off, as the cloud packet does

    if settings.light_power is False:
        props.append((0xF3, b"\x31"))
    elif settings.light_power:
        props.append((0xF3, b"\x30"))
        if settings.light_mode == "night":
            props.append((0xF4, b"\x43"))
            if settings.light_night_light_brightness is not None:
                level = {"low": 0x01, "medium": 0x32, "high": 0x64}[
                    settings.light_night_light_brightness
                ]
                props.append((0xF7, bytes([level])))
        elif settings.light_mode == "day":
            props.append((0xF4, b"\x42"))
            if settings.light_brightness:
                props.append((0xF5, bytes([min(100, max(1, settings.light_brightness))])))
            if settings.light_colour is not None:
                props.append((0xF6, bytes([min(100, max(0, settings.light_colour))])))
    elif settings.light_mode or settings.light_brightness or settings.light_colour:
        raise ValueError("light settings need light_power - the fan refuses them otherwise")

    return props


class LocalTransport(asyncio.DatagramProtocol):
    """The UDP socket the fans talk back to.

    A fan replies *from* an ephemeral port *to* port 3610, not to the sender's
    port, so this must be bound to 3610 - and only one process per host can be.
    Requests are matched to replies by TID, which also lets any number of them
    be in flight at once.
    """

    # Resend after this long without a reply. Covers measured packet loss
    # (0.6-2.5%) and a cold ARP cache. Requests are absolute values, so a
    # duplicate that does get through is harmless.
    RESEND_AFTER = 1.0

    def __init__(self) -> None:
        """Initialise; use LocalTransport.create() to bind."""
        self._transport: asyncio.DatagramTransport | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._tid = 0

    @classmethod
    async def create(cls, host: str = "0.0.0.0") -> LocalTransport:
        """Bind UDP 3610. Raises OSError if the port is taken."""
        loop = asyncio.get_running_loop()
        protocol = cls()
        await loop.create_datagram_endpoint(
            lambda: protocol, local_addr=(host, EL_PORT)
        )
        return protocol

    def connection_made(self, transport) -> None:
        """Store the transport."""
        self._transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        """Resolve the request this reply belongs to."""
        try:
            tid, esv, props = parse_frame(data)
        except ValueError:
            return
        future = self._pending.get(tid)
        if future is not None and not future.done():
            future.set_result((esv, props))

    def error_received(self, exc: Exception) -> None:
        """Log send errors; the resend loop covers transient ones."""
        LOGGER.debug(f"Local transport error: {exc}")

    def connection_lost(self, exc: Exception | None) -> None:
        """Fail anything still waiting."""
        self._transport = None
        for future in self._pending.values():
            if not future.done():
                future.set_exception(ConnectionError("local transport closed"))

    def close(self) -> None:
        """Release UDP 3610."""
        if self._transport is not None:
            self._transport.close()

    def _next_tid(self) -> int:
        while True:
            self._tid = self._tid % 0xFFFF + 1
            if self._tid not in self._pending:
                return self._tid

    async def request(
        self, ip: str, esv: int, props: Props, timeout: float = 3.0
    ) -> tuple[int, Props]:
        """Send a request and return the fan's (esv, props).

        Raises TimeoutError if no reply arrives within `timeout`.
        """
        if self._transport is None:
            raise ConnectionError("local transport is not open")
        loop = asyncio.get_running_loop()
        tid = self._next_tid()
        future = loop.create_future()
        self._pending[tid] = future
        frame = build_frame(tid, esv, props)
        deadline = loop.time() + timeout
        try:
            while True:
                if self._transport is None:
                    raise ConnectionError("local transport closed")
                self._transport.sendto(frame, (ip, EL_PORT))
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise TimeoutError(f"no reply from {ip}")
                try:
                    return await asyncio.wait_for(
                        asyncio.shield(future), min(self.RESEND_AFTER, remaining)
                    )
                except TimeoutError:
                    if loop.time() >= deadline:
                        raise TimeoutError(f"no reply from {ip}") from None
        finally:
            self._pending.pop(tid, None)
            if not future.done():
                future.cancel()


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.found: dict[str, str] = {}

    def datagram_received(self, data: bytes, addr) -> None:
        headers = {}
        for line in data.decode("utf-8", "replace").split("\r\n"):
            if match := _SSDP_HEADER.match(line):
                headers[match.group(1).upper()] = match.group(2).strip()
        if guid := headers.get("HASHGUID"):
            self.found[guid] = headers.get("LOCATION") or addr[0]

    def error_received(self, exc: Exception) -> None:
        # e.g. 255.255.255.255 is unroutable on some hosts; other targets still work
        LOGGER.debug(f"Discovery send error: {exc}")


def subnet_broadcast_addresses(adapters: list[dict]) -> list[str]:
    """Subnet-directed broadcast address of every enabled IPv4 adapter.

    Takes Home Assistant's network adapter list. The fans answer only a
    subnet-directed broadcast such as 192.168.1.255 and ignore 255.255.255.255,
    which is all that network.async_get_ipv4_broadcast_addresses returns under
    HA's default network settings - hence computing it here.
    """
    addresses = set()
    for adapter in adapters:
        if not adapter.get("enabled"):
            continue
        for ip_info in adapter.get("ipv4", []):
            interface = ipaddress.ip_interface(
                f"{ip_info['address']}/{ip_info['network_prefix']}"
            )
            if interface.ip.is_loopback or interface.network.prefixlen >= 31:
                continue  # no broadcast address on loopback or point-to-point links
            addresses.add(str(interface.network.broadcast_address))
    return sorted(addresses)


async def async_discover(
    broadcast_addrs: list[str], timeout: float = 4.0, attempts: int = 3
) -> dict[str, str]:
    """Find fans on the LAN. Returns {HASHGUID: ip}.

    The fans don't do mDNS or port-1900 SSDP; this M-SEARCH on 50125, sent to
    the subnet broadcast address, is the only thing they answer. HASHGUID equals
    hashed_guid from the cloud device list.
    """
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        _DiscoveryProtocol, local_addr=("0.0.0.0", 0), allow_broadcast=True
    )
    try:
        for _ in range(attempts):
            for addr in broadcast_addrs:
                transport.sendto(MSEARCH.format(host=addr).encode(), (addr, SSDP_PORT))
            await asyncio.sleep(1.0)
        await asyncio.sleep(max(0.0, timeout - attempts))
    finally:
        transport.close()
    return dict(protocol.found)
