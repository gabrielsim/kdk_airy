"""Light platform for integration_blueprint."""

import math

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP,
    ColorMode,
    LightEntity,
    LightEntityDescription,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util.color import (
    color_temperature_kelvin_to_mired as kelvin_to_mired,
    value_to_brightness,
)

from .api import KdkApiClient, KdkDeviceSettings
from .const import LOGGER
from .coordinator import KdkAiryDataUpdateCoordinator
from .data import KdkConfigEntry

MIN_KELVIN = 3000  # Warmest temperature, API = 0%
MAX_KELVIN = 7000  # Coolest temperature, API = 100%
DEFAULT_KELVIN = 6000  # Cloudy
MAX_BRIGHTNESS = 255


async def async_setup_entry(
    hass: HomeAssistant,
    entry: KdkConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the light platform."""

    async_add_entities(
        IntegrationBlueprintLight(
            coordinator=entry.runtime_data.coordinator,
            entity_description=LightEntityDescription(
                key=f"{device.appliance_id}_light",
                name=device.name,
                icon="mdi:ceiling-fan-light",
            ),
            appliance_id=device.appliance_id,
            api=entry.runtime_data.client,
        )
        for device in filter(
            lambda x: x.has_lights,
            (await entry.runtime_data.client.get_registered_fans()),
        )
    )


class IntegrationBlueprintLight(CoordinatorEntity, LightEntity):
    """integration_blueprint light class."""

    def __init__(
        self,
        coordinator: KdkAiryDataUpdateCoordinator,
        entity_description: LightEntityDescription,
        appliance_id: str,
        api: KdkApiClient,
    ) -> None:
        """Initialize the light class."""
        super().__init__(coordinator=coordinator)
        self.entity_description = entity_description
        self._attr_is_on = False
        self._attr_brightness = MAX_BRIGHTNESS  # Range from 1..255
        self._attr_color_temp = kelvin_to_mired(DEFAULT_KELVIN)
        self._attr_min_mireds = kelvin_to_mired(MAX_KELVIN)
        self._attr_max_mireds = kelvin_to_mired(MIN_KELVIN)
        self._attr_supported_color_modes = {ColorMode.COLOR_TEMP}
        self._attr_color_mode = ColorMode.COLOR_TEMP
        self._appliance_id = appliance_id
        self._api = api
        self._attr_unique_id = f"{appliance_id}_light"

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
    def name(self) -> str:
        """Return the name of this light."""
        return self.entity_description.name

    @property
    def brightness_pct(self):
        """Return the brightness percentage of the light."""
        return max(
            0,
            min(100, math.ceil(self._attr_brightness / MAX_BRIGHTNESS * 10) * 10),
        )

    @property
    def color_percentage(self):
        """Return the color percentage of the light."""

        return max(
            0,
            min(
                100,
                int(
                    (self.color_temp_kelvin - MIN_KELVIN)
                    / (MAX_KELVIN - MIN_KELVIN)
                    * 100
                ),
            ),
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device_settings: KdkDeviceSettings = self.coordinator.data.get(
            self._appliance_id
        )

        if not device_settings:
            self.async_write_ha_state()  # mark device as unavailable
            return

        self._attr_is_on = device_settings.light_power
        if device_settings.light_mode == "day":
            self._attr_brightness = value_to_brightness(
                (1, 100), device_settings.light_brightness
            )
            self._attr_color_temp = kelvin_to_mired(
                MIN_KELVIN
                + device_settings.light_colour * ((MAX_KELVIN - MIN_KELVIN) / 100)
            )
        elif device_settings.light_mode == "night":
            self._attr_brightness = value_to_brightness(
                (1, 100),
                {"low": 10, "medium": 20, "high": 30}[
                    device_settings.light_night_light_brightness
                ],
            )
        self.async_write_ha_state()

    async def async_set_light_settings(self, settings: KdkDeviceSettings) -> None:
        """Set light to the desired settings."""

        LOGGER.info(f"Set light settings: {settings}")

        await self._api.change_settings(
            appliance_id=self._appliance_id,
            desired_setting=settings,
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the light on."""
        self._attr_is_on = True
        if ATTR_BRIGHTNESS in kwargs:
            self._attr_brightness = math.ceil(
                kwargs[ATTR_BRIGHTNESS] / (MAX_BRIGHTNESS / 10)
            ) * (MAX_BRIGHTNESS / 10)
        if ATTR_COLOR_TEMP in kwargs:
            self._attr_color_temp = kwargs[ATTR_COLOR_TEMP]
        self.async_write_ha_state()

        if self.brightness_pct in [10, 20, 30]:
            # Set night light
            await self.async_set_light_settings(
                KdkDeviceSettings(
                    light_power=self._attr_is_on,
                    light_mode="night",
                    light_night_light_brightness={10: "low", 20: "medium", 30: "high"}[
                        self.brightness_pct
                    ],
                )
            )
        else:
            await self.async_set_light_settings(
                KdkDeviceSettings(
                    light_power=self._attr_is_on,
                    light_mode="day",
                    light_brightness=self.brightness_pct,
                    light_colour=self.color_percentage,
                )
            )

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the light off."""

        self._attr_is_on = False
        self.async_write_ha_state()
        await self.async_set_light_settings(KdkDeviceSettings(fan_power=False))
