"""Fan and light settings for a single combined command.

Pure logic with no Home Assistant imports, so it can be tested on its own. The
conventions match the fan and light entities: percentages round up to the next
10%, and light brightness of 10% / 20% / 30% means night light low / medium / high.
"""

from __future__ import annotations

import math

from .api import KdkDeviceSettings
from .const import DEFAULT_KELVIN, MAX_KELVIN, MIN_KELVIN

NIGHT_LIGHT_LEVELS = {10: "low", 20: "medium", 30: "high"}


def kelvin_to_colour(kelvin: int) -> int:
    "Convert a colour temperature to the fan's 0 (warm) - 100 (white) scale."
    return max(0, min(100, int((kelvin - MIN_KELVIN) / (MAX_KELVIN - MIN_KELVIN) * 100)))


def _round_up_to_step(percentage: int) -> int:
    return min(100, math.ceil(percentage / 10) * 10)


def combined_settings(
    current: KdkDeviceSettings | None,
    has_lights: bool,
    fan_percentage: int | None = None,
    fan_direction: str | None = None,
    light_brightness_pct: int | None = None,
    light_color_temp_kelvin: int | None = None,
) -> KdkDeviceSettings:
    """Build one KdkDeviceSettings covering both the fan and the light.

    Anything not given keeps its current value. 0% turns that part off.
    Raises ValueError for requests the fan can't carry out.
    """
    touches_fan = fan_percentage is not None or fan_direction is not None
    touches_light = (
        light_brightness_pct is not None or light_color_temp_kelvin is not None
    )
    if not touches_fan and not touches_light:
        raise ValueError("Give at least one fan or light setting")
    if touches_light and not has_lights:
        raise ValueError("This fan has no light")

    settings = KdkDeviceSettings()

    if touches_fan:
        percentage = fan_percentage
        if percentage is None:  # direction only: keep the current speed
            if not (current and current.fan_power and current.fan_volume):
                raise ValueError(
                    "The fan is off; give fan_percentage to set its direction"
                )
            percentage = current.fan_volume
        if percentage == 0:
            settings.fan_power = False
        else:
            settings.fan_power = True
            settings.fan_volume = _round_up_to_step(percentage)
            settings.fan_direction = (
                fan_direction or (current and current.fan_direction) or "forward"
            )

    if touches_light:
        brightness = light_brightness_pct
        if brightness is None:  # colour only: keep the current day brightness
            brightness = (current and current.light_brightness) or 100
        if brightness == 0:
            settings.light_power = False
        else:
            brightness = _round_up_to_step(brightness)
            settings.light_power = True
            if brightness in NIGHT_LIGHT_LEVELS:
                if light_color_temp_kelvin is not None:
                    raise ValueError(
                        "Night light (10/20/30% brightness) has no colour "
                        "temperature; the fan refuses colour in night mode"
                    )
                settings.light_mode = "night"
                settings.light_night_light_brightness = NIGHT_LIGHT_LEVELS[brightness]
            else:
                settings.light_mode = "day"
                settings.light_brightness = brightness
                if light_color_temp_kelvin is not None:
                    settings.light_colour = kelvin_to_colour(light_color_temp_kelvin)
                elif current and current.light_colour is not None:
                    settings.light_colour = current.light_colour
                else:
                    settings.light_colour = kelvin_to_colour(DEFAULT_KELVIN)

    return settings
