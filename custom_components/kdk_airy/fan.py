"""Fan platform for integration_blueprint."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from homeassistant.components.fan import (
    FanEntity,
    FanEntityDescription,
    FanEntityFeature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity, callback
from homeassistant.util.percentage import int_states_in_range

from .api import KdkApiClient, KdkDeviceSettings
from .const import LOGGER
from .coordinator import KdkAiryDataUpdateCoordinator
from .data import KdkConfigEntry

WIND_SPEED_RANGE = (1, 10)  # Min and max speed, 1-10
Direction = Literal["forward", "reverse"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the fan platform."""

    async_add_entities(
        IntegrationBlueprintFan(
            coordinator=entry.runtime_data.coordinator,
            entity_description=FanEntityDescription(
                key=f"{device.appliance_id}_fan",
                name=device.name,
                icon="mdi:ceiling-fan",
            ),
            appliance_id=device.appliance_id,
            api=entry.runtime_data.client,
        )
        for device in (await entry.runtime_data.client.get_registered_fans())
    )


class IntegrationBlueprintFan(CoordinatorEntity, FanEntity):
    """Representation of an Integration Blueprint Fan."""

    def __init__(
        self,
        coordinator: KdkAiryDataUpdateCoordinator,
        entity_description: FanEntityDescription,
        appliance_id: str,
        api: KdkApiClient,
    ) -> None:
        """Initialize the fan."""
        super().__init__(coordinator=coordinator)
        self.entity_description = entity_description
        self._attr_unique_id = f"{entity_description.key}_fan"
        self._attr_supported_features = (
            FanEntityFeature.TURN_ON
            | FanEntityFeature.TURN_OFF
            | FanEntityFeature.SET_SPEED
            | FanEntityFeature.DIRECTION
        )
        self._attr_speed_count = int_states_in_range(WIND_SPEED_RANGE)
        self._attr_is_on = False
        self._attr_percentage = 0
        self._attr_current_direction: Direction = "forward"
        self._appliance_id = appliance_id
        self._api = api
        self._attr_unique_id = f"{appliance_id}_fan"
        self._last_change = datetime(1970, 1, 1)

    @property
    def available(self):
        """Return if entity is available."""
        return (
            self.coordinator.last_update_success
            and self._appliance_id in self.coordinator.data
        )

    async def async_added_to_hass(self) -> None:
        """Run when entity about to be added to hass."""
        await super().async_added_to_hass()
        self._handle_coordinator_update()

    @property
    def current_direction(self) -> Direction:
        """Return the current direction of the fan."""
        return self._attr_current_direction

    @property
    def speed_count(self) -> int:
        """Return the number of speeds the fan supports."""
        return self._attr_speed_count

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""

        if self.coordinator.data["polled_time"] < self._last_change.timestamp():
            LOGGER.warning("Coordinator data is stale, skipping")
            return

        device_settings: KdkDeviceSettings = self.coordinator.data.get(
            self._appliance_id
        )

        if not device_settings:
            self.async_write_ha_state()  # mark device as unavailable
            return

        self._attr_is_on = device_settings.fan_power
        self._attr_current_direction = device_settings.fan_direction
        self._attr_percentage = device_settings.fan_volume

        self.async_write_ha_state()

    async def async_set_fan_settings(self, settings: KdkDeviceSettings) -> None:
        """Set fan to the desired settings."""

        self._attr_is_on = settings.fan_power
        self._attr_percentage = settings.fan_volume
        self._attr_current_direction = settings.fan_direction

        self.async_write_ha_state()
        self._last_change = datetime.now()

        await self._api.change_settings(
            appliance_id=self._appliance_id,
            desired_setting=settings,
        )

    async def async_set_percentage(self, percentage: int) -> None:
        """Set the speed percentage of the fan."""

        await self.async_set_fan_settings(
            KdkDeviceSettings(
                fan_power=(percentage > 0),
                fan_volume=percentage,
                fan_direction=self._attr_current_direction
                or "forward",  # default to forward
            )
        )

    async def async_set_direction(self, direction: Direction) -> None:
        """Set the direction of the fan."""

        LOGGER.info(f"Set fan direction: {direction}")

        if self._attr_is_on is None:
            # If fan_power is unknown, only set ha_state
            self._attr_current_direction = direction
            self.async_write_ha_state()
        else:
            if self._attr_percentage is None:
                fan_volume = 100 if self._attr_is_on else 0
            else:
                fan_volume = self._attr_percentage

            await self.async_set_fan_settings(
                KdkDeviceSettings(
                    fan_power=self._attr_is_on,
                    fan_volume=fan_volume,
                    fan_direction=direction,
                )
            )

    async def async_turn_on(
        self,
        percentage: int | None = None,
        preset_mode: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Turn on the fan."""

        await self.async_set_fan_settings(
            KdkDeviceSettings(
                fan_power=True,
                fan_volume=percentage or 100,  # default to highest speed (100%)
                fan_direction=self._attr_current_direction
                or "forward",  # default to forward direction
            )
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the fan off."""

        await self.async_set_fan_settings(KdkDeviceSettings(fan_power=False))
