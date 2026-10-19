"""Tests for the kdk_airy.set_fan_and_light action."""

from unittest.mock import AsyncMock, patch

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.exceptions import ServiceValidationError
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.kdk_airy.api import (
    CommandInvalid,
    KdkApiClient,
    KdkDevice,
    KdkDeviceSettings,
)
from custom_components.kdk_airy.client import KdkHybridClient
from custom_components.kdk_airy.combined import apply_settings, combined_settings
from custom_components.kdk_airy.const import DOMAIN

KNOWN = KdkDevice("a1", "g1", "", "", "E48GP", "Bed", True)
UNTESTED = KdkDevice("a3", "g3", "", "", "Z99", "New", None)

STATUS = KdkDeviceSettings(
    fan_power=False,
    fan_volume=40,
    fan_direction="forward",
    light_power=False,
    light_mode="day",
    light_brightness=60,
    light_colour=50,
)

# ------------------------------------------------------------ combined_settings


def test_on_at_last_settings():
    s = combined_settings(STATUS, True, fan_on=True, light_on=True)
    assert (s.fan_power, s.fan_volume, s.fan_direction) == (True, 40, "forward")
    assert (s.light_power, s.light_mode, s.light_brightness, s.light_colour) == (
        True,
        "day",
        60,
        50,
    )


def test_light_on_from_night_keeps_night_level():
    current = KdkDeviceSettings(
        light_mode="night", light_night_light_brightness="medium", light_brightness=70
    )
    s = combined_settings(current, True, light_on=True)
    assert (s.light_mode, s.light_night_light_brightness) == ("night", "medium")


@pytest.mark.parametrize("day_brightness", [20, 25, 30])
def test_colour_only_keeps_a_low_day_brightness(day_brightness):
    current = KdkDeviceSettings(
        light_power=True, light_mode="day", light_brightness=day_brightness
    )
    s = combined_settings(current, True, light_color_temp_kelvin=5000)
    assert (s.light_mode, s.light_brightness, s.light_colour) == (
        "day",
        day_brightness,
        50,
    )


def test_explicit_night_level_refuses_colour():
    with pytest.raises(ValueError, match="no colour"):
        combined_settings(STATUS, True, light_brightness_pct=20, light_color_temp_kelvin=5000)


def test_explicit_levels_round_up():
    s = combined_settings(STATUS, True, fan_percentage=82, light_brightness_pct=41)
    assert (s.fan_volume, s.light_brightness) == (90, 50)
    assert combined_settings(STATUS, True, light_brightness_pct=15).light_mode == "night"


def test_light_refused_when_unknown_or_absent():
    with pytest.raises(ValueError, match="hasn't reported yet"):
        combined_settings(STATUS, None, light_on=True)
    with pytest.raises(ValueError, match="has no light"):
        combined_settings(STATUS, False, light_on=True)
    # fan-only requests don't need to know
    assert combined_settings(STATUS, None, fan_on=True).fan_power is True


def test_apply_settings_keeps_what_the_fan_remembers():
    after = apply_settings(STATUS, KdkDeviceSettings(fan_power=False, light_power=True, light_mode="night", light_night_light_brightness="low"))
    assert (after.fan_power, after.fan_volume) == (False, 40)
    assert (after.light_power, after.light_mode, after.light_brightness) == (True, "night", 60)
    assert apply_settings(None, KdkDeviceSettings(fan_power=True)).fan_power is True


# ------------------------------------------------------------ the action


@pytest.fixture
async def setup(hass):
    """Set up the integration with the given fans, cloud-only and mocked."""
    patches = []

    async def _setup(devices, status):
        entry = MockConfigEntry(
            domain=DOMAIN, unique_id="x", data={CONF_USERNAME: "a", CONF_PASSWORD: "p"}
        )
        entry.add_to_hass(hass)
        patches.extend(
            [
                patch.object(KdkApiClient, "get_registered_fans", AsyncMock(return_value=devices)),
                patch.object(KdkApiClient, "get_statuses", AsyncMock(return_value=status)),
                patch.object(KdkHybridClient, "async_start", AsyncMock()),
                patch(
                    "custom_components.kdk_airy.network.async_get_adapters",
                    AsyncMock(return_value=[]),
                ),
            ]
        )
        for p in patches:
            p.start()
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        return entry

    yield _setup
    for p in patches:
        p.stop()


async def _call(hass, entity_id, **data):
    await hass.services.async_call(
        DOMAIN, "set_fan_and_light", {"entity_id": entity_id, **data}, blocking=True
    )


async def test_one_command_and_both_entities_update_at_once(hass, setup):
    entry = await setup([KNOWN], {"a1": STATUS})
    coordinator = entry.runtime_data.coordinator
    with (
        patch.object(KdkHybridClient, "change_settings", AsyncMock()) as change,
        patch.object(coordinator, "async_request_refresh", AsyncMock()),
    ):
        await _call(hass, "fan.bed", fan_on=True, light_on=True)
    assert change.await_count == 1
    assert hass.states.get("fan.bed").state == "on"
    assert hass.states.get("light.bed").state == "on"


async def test_untested_model_light_detected_after_setup(hass, setup):
    await setup([UNTESTED], {"a3": STATUS})
    assert hass.states.get("light.new") is not None
    with patch.object(KdkHybridClient, "change_settings", AsyncMock()) as change:
        await _call(hass, "fan.new", light_on=True)
    assert change.await_args.kwargs["desired_setting"].light_power is True


async def test_unanswered_fan_is_skipped(hass, setup):
    # No status yet: the fan is unavailable and Home Assistant skips it
    await setup([UNTESTED], {})
    with patch.object(KdkHybridClient, "change_settings", AsyncMock()) as change:
        await _call(hass, "fan.new", light_on=True)
    change.assert_not_called()


async def test_invalid_request_is_a_validation_error(hass, setup):
    await setup([KNOWN], {"a1": STATUS})
    with pytest.raises(ServiceValidationError, match="fan_on is false"):
        await _call(hass, "fan.bed", fan_on=False, fan_percentage=50)


async def test_failed_command_reverts_fan_state(hass, setup):
    await setup([KNOWN], {"a1": STATUS})
    assert hass.states.get("fan.bed").state == "off"
    with (
        patch.object(
            KdkHybridClient, "change_settings", AsyncMock(side_effect=CommandInvalid("busy"))
        ),
        pytest.raises(CommandInvalid),
    ):
        await _call(hass, "fan.bed", fan_on=True, light_on=True)
    assert hass.states.get("fan.bed").state == "off"
    assert hass.states.get("light.bed").state == "off"
