"""KDK API Package."""

import asyncio
import contextlib
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Literal, NamedTuple

import aiohttp

from .const import LOGGER


class KdkApiError(Exception):
    "Parent class for KDK command errors."


class CommandResultNotReady(KdkApiError):
    "Command results is still pending."


class CommandResultNotFound(KdkApiError):
    "Command results is not in the response."


class DeviceOffline(KdkApiError):
    "KDK device is turned off / unresponsive."


class CommandInvalid(KdkApiError):
    "Sent command is marked as invalid from server."


class AuthExpired(KdkApiError):
    "When the auth token has expired. It can happen either after 24 hours, or another device has logged in."


class InvalidAuth(KdkApiError):
    "Invalid username / password used."


class KdkDevice(NamedTuple):
    "Represents a KDK device."

    appliance_id: str
    hashed_guid: str
    serial_number: str
    com_id: str
    product_code: str
    name: str

    @property
    def has_lights(self):
        "Whether the fan device also has lights."
        return self.product_code in ["E48GP"]


@dataclass
class KdkDeviceSettings:
    "Represents the KDK Device settings."

    fan_power: bool | None = None
    fan_volume: int | None = (
        None  # Valid values are 10, 20, ... 90, 100 (increment of 10)
    )
    fan_direction: Literal["forward", "reverse"] | None = None

    has_light: bool | None = True
    light_power: bool | None = None
    light_mode: Literal["day", "night"] | None = None
    light_brightness: int | None = None  # Valid values are [0, 100] (increment of 1)
    light_colour: int | None = (
        None  # Valid values are [0 (warm), 100 (white)] (increment of 1)
    )
    light_night_light_brightness: Literal["low", "medium", "high"] | None = None

    @staticmethod
    def parse_data_packet(packet: str):
        "Parse the packet and return the parsed KdkDeviceSettings."

        settings = KdkDeviceSettings()

        with contextlib.suppress(Exception):
            settings.fan_power = {"0": True, "1": False}[
                re.findall(r"(?<=0080013)\w{1}", packet)[0]
            ]

        with contextlib.suppress(Exception):
            settings.fan_volume = (
                int(re.findall(r"(?<=00F0013)\w{1}", packet)[0], 16) * 10
            )

        with contextlib.suppress(Exception):
            settings.fan_direction = {"1": "forward", "2": "reverse"}[
                re.findall(r"(?<=00F1014)\w{1}", packet)[0]
            ]

        with contextlib.suppress(Exception):
            settings.light_power = {"0": True, "1": False}[
                re.findall(r"(?<=00F3013)\w{1}", packet)[0]
            ]

        with contextlib.suppress(Exception):
            settings.light_mode = {"2": "day", "3": "night"}[
                re.findall(r"(?<=00F4014)\w{1}", packet)[0]
            ]

        with contextlib.suppress(Exception):
            settings.light_brightness = int(
                re.findall(r"(?<=00F501)\w{2}", packet)[0], 16
            )

        with contextlib.suppress(Exception):
            settings.light_colour = int(re.findall(r"(?<=00F601)\w{2}", packet)[0], 16)

        with contextlib.suppress(Exception):
            settings.light_night_light_brightness = {
                "64": "high",
                "32": "medium",
                "01": "low",
            }[re.findall(r"(?<=00F701)\w{2}", packet)[0]]

        return settings

    def create_command_packet(self):
        "Generate the packet with the desired (with defaults) settings."

        # self.set_defaults()

        remote_ctl_setting = "930142"
        ctl_opt_source = "FD0104"
        buzzer = "FC0130"
        melody = "FE0140"
        fan_power = {True: "800130", False: "800131"}.get(self.fan_power, None)
        if self.fan_power:
            fan_volume = f"F0013{format(int(self.fan_volume/10), 'X')}"
            fan_direction = {"forward": "F10141", "reverse": "F10142"}[
                self.fan_direction
            ]
            fan_yuragi = "F20131"
        else:
            fan_volume = None
            fan_direction = None
            fan_yuragi = None

        light_power = {True: "F30130", False: "F30131"}.get(self.light_power, None)
        light_mode = {"day": "F40142", "night": "F40143"}.get(self.light_mode, None)
        light_brightness = (
            f"F501{format(self.light_brightness, 'X').rjust(2, '0')}"
            if self.light_brightness
            else None
        )
        light_colour = (
            f"F601{format(self.light_colour, 'X').rjust(2, '0')}"
            if self.light_colour is not None
            else None
        )
        light_night_light_brightness = {
            "low": "F70101",
            "medium": "F70132",
            "high": "F70164",
        }.get(self.light_night_light_brightness, None)
        fan_off_timer = "F804FF31FFFF"

        delimiter = "00"

        all_settings = [
            remote_ctl_setting,
            ctl_opt_source,
            buzzer,
            melody,
            fan_power,
            fan_volume,
            fan_direction,
            fan_yuragi,
            light_power,
            light_mode,
            light_brightness,
            light_colour,
            light_night_light_brightness,
            fan_off_timer,
        ]

        all_settings = [
            x for x in all_settings if x is not None
        ]  # Remove empty configs

        all_settings.insert(0, f"{len(all_settings):02X}")

        return delimiter.join(all_settings)


class KdkApiClient:
    "KDK API client."

    SUPPORTED_PRODUCT_CODES = [
        "E48HP",
        "E48GP",
    ]

    # Hard-coded values from the KDK Ceiling Fan app v1.1.0
    APP_KEY = "rZLwuRtU0nFb20Mh6LShL6uY3fZ5tBlarz4ONmdl"
    USER_AGENT = "CeilingFanKDK_prod_appStore/1.1.0 (iPhone; iOS 16.4.1; Scale/3.00)"

    def __init__(
        self,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
    ) -> None:
        "Initiate the KDK API client."

        self._username = username
        self._password = password
        self._session = session

        self._token = None

        LOGGER.info("KDK API client initiated")

    @staticmethod
    async def _log_response_time(resp: aiohttp.ClientResponse, start_time: float):
        "Log the request duration."
        duration = asyncio.get_event_loop().time() - start_time
        LOGGER.debug(f"Request took {round(duration, 1)}s")

    async def login(self):
        "Login to server."

        LOGGER.debug("Logging in")

        async with self._session.post(
            url="https://prod.mycfan.pgtls.net/v1/mycfan/auth/login",
            json={
                "type": 1,
                "id": self._username,
                "pass": self._password,
            },
            headers={"x-api-key": KdkApiClient.APP_KEY},
        ) as response:
            if response.status == 401:
                raise InvalidAuth(await response.text())
            response.raise_for_status()
            data = await response.json()
            self._token = data["token"]

        LOGGER.debug("Logged in successfully")

    def get_auth_headers(self):
        "Get the authentication headers."
        return {
            "Authorization": self._token,
            "X-Timestamp": datetime.now(UTC).strftime("%Y%m%d%H%M%S"),
            "x-api-key": KdkApiClient.APP_KEY,
            "User-Agent": KdkApiClient.USER_AGENT,
        }

    async def _make_request(self, method: str, url: str, **kwargs):
        "Make an authenticated request."
        if not self._token:
            await self.login()

        headers = self.get_auth_headers()
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers

        start_time = asyncio.get_event_loop().time()

        async with self._session.request(method, url, **kwargs) as response:
            await self._log_response_time(response, start_time)

            if response.status == 401:
                raise AuthExpired(await response.text())
            response.raise_for_status()

            return await response.json()

    async def get_registered_fans(self):
        """Return a list of registered fans (includes offline) to the account,`
        filtered by supported product codes."""
        data = await self._make_request(
            "GET", "https://prod.mycfan.pgtls.net/v1/mycfan/user/devices"
        )
        return [
            KdkDevice(**device)
            for device in data["devices"]
            if device.get("product_code") in KdkApiClient.SUPPORTED_PRODUCT_CODES
        ]

    async def get_statuses(
        self, devices: list[KdkDevice]
    ) -> dict[str, KdkDeviceSettings]:
        "Get the current state of the devices and returns in the format { appliance_id: KdkDeviceSettings}."

        if not devices:
            return []

        sent_commands = {}

        for device in devices:
            get_status_packet = {
                "E48HP": "0A00800000F00000860000880000F80000F20000F10000F90000FA0000FB00",
                "E48GP": "0F00800000F00000860000880000F80000F20000F10000F90000FA0000FB0000F30000F50000F40000F70000F600",
            }[device.product_code]

            command_request_id = await self.send_command(
                method="GET",
                packet=get_status_packet,
                appliance_id=device.appliance_id,
            )
            sent_commands[device.appliance_id] = command_request_id

            LOGGER.debug(
                f"Command sent, waiting for command results {command_request_id}"
            )

        command_results = await self.get_command_results(
            command_request_ids=list(sent_commands.values())
        )

        statuses = {}

        for command_result_id, result in command_results.items():
            appliance_id = next(
                (key for key, val in sent_commands.items() if val == command_result_id),
                None,
            )

            if not appliance_id:
                continue

            if isinstance(result, Exception):
                appliance_name = next(
                    x.name for x in devices if x.appliance_id == appliance_id
                )
                LOGGER.warning(
                    f"Failed to get status for {appliance_name}: {result.__class__.__name__}"
                )
                continue

            statuses[appliance_id] = KdkDeviceSettings.parse_data_packet(
                packet=result["packet"]
            )

        return statuses

    async def change_settings(
        self, appliance_id: str, desired_setting: KdkDeviceSettings
    ):
        "Update the state of the device."

        packet = desired_setting.create_command_packet()
        LOGGER.debug(f"Sent packet = {packet}")

        command_request_id = await self.send_command(
            method="SET", appliance_id=appliance_id, packet=packet
        )
        LOGGER.debug(f"Requested change request ID: {command_request_id}")

        command_result = await self.get_command_result(
            command_request_id=command_request_id
        )
        LOGGER.debug(f"Result = {command_result}")

    async def send_command(
        self, method: Literal["SET", "GET"], appliance_id: str, packet: str
    ):
        "Send the command to device."

        data = await self._make_request(
            "POST",
            "https://prod.mycfan.pgtls.net/v1/mycfan/deviceControls",
            json={
                "appliance_id": appliance_id,
                "method": method,
                "packet": packet,
            },
        )

        return data["accepted_id"]

    async def get_command_result(self, command_request_id: str):
        "Get the result for the sent command."

        for _ in range(6):  # Prevent excessive API calls
            data = await self._make_request(
                "GET",
                "https://prod.mycfan.pgtls.net/v1/mycfan/deviceControls",
            )

            command_results: list[dict] = data["controls"]

            response: dict = next(
                filter(
                    lambda x: x.get("accepted_id", None) == command_request_id,
                    command_results,
                ),
                None,
            )

            if not response:
                raise CommandResultNotFound

            status = response.get("status")
            result = response.get("result")

            if status == "inprogress":
                LOGGER.warning(response)
                await asyncio.sleep(1)  # Wait before retrying
                continue

            if status == "complete":
                if result == "no_response":
                    raise DeviceOffline(response)
                if result == "error_response":
                    raise CommandInvalid(response)
                if result == "success_response":
                    return response

            raise CommandInvalid(response)

        raise CommandResultNotReady(response)

    async def get_command_results(self, command_request_ids: list[str]):
        "Get the results for the sent commands in the format  { command_request_id: Result | Exception }."

        command_results = {}

        for command_request_id in command_request_ids:
            command_results.setdefault(command_request_id, CommandResultNotFound())

        for _ in range(6):  # Prevent excessive API calls
            try:
                await asyncio.sleep(1)  # Throttle
                data = await self._make_request(
                    "GET",
                    "https://prod.mycfan.pgtls.net/v1/mycfan/deviceControls",
                )

                for command_result in data["controls"]:
                    command_result_id = command_result.get("accepted_id")
                    status = command_result.get("status")
                    result = command_result.get("result")

                    if command_result_id not in command_request_ids:
                        continue

                    if status == "inprogress":
                        command_results[command_result_id] = CommandResultNotReady()
                        continue

                    if status == "complete":
                        if result == "no_response":
                            command_results[command_result_id] = DeviceOffline(
                                command_result
                            )
                            continue
                        if result == "error_response":
                            command_results[command_result_id] = CommandInvalid(
                                command_result
                            )
                            continue
                        if result == "success_response":
                            command_results[command_result_id] = command_result
                            continue

                    command_results[command_result_id] = CommandInvalid(command_result)
            except Exception as error:  # noqa: BLE001
                LOGGER.error(error)

            should_poll_again = False

            for result in command_results.values():
                if isinstance(result, (CommandResultNotReady, CommandResultNotFound)):
                    should_poll_again = True
                    break

            if not should_poll_again:
                break

        return command_results
