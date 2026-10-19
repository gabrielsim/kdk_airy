"""Adds config flow for KDK Airy."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant import config_entries, data_entry_flow
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .api import InvalidAuth, KdkApiClient, KdkApiError
from .const import DOMAIN, LOGGER


class KdkAiryFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for KDK Airy."""

    VERSION = 1

    async def async_step_user(
        self,
        user_input: dict | None = None,
    ) -> data_entry_flow.FlowResult:
        """Handle a flow initialized by the user."""
        _errors = {}
        if user_input is not None:
            # Assign a unique ID to the flow and abort the flow
            # if another flow with the same unique ID is in progress
            device_unique_id = user_input[CONF_USERNAME].lower()
            await self.async_set_unique_id(device_unique_id)
            # Abort the flow if a config entry with the same unique ID exists
            self._abort_if_unique_id_configured()

            _errors = await self._test_credentials(
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
            )
            if not _errors:
                return self.async_create_entry(
                    title=user_input[CONF_USERNAME],
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME,
                        default=(user_input or {}).get(CONF_USERNAME, vol.UNDEFINED),
                    ): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.TEXT,
                        ),
                    ),
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD,
                        ),
                    ),
                },
            ),
            errors=_errors,
        )

    async def _test_credentials(self, username: str, password: str) -> dict[str, str]:
        """Validate credentials, returning form errors."""
        client = KdkApiClient(
            username=username,
            password=password,
            session=async_create_clientsession(self.hass),
        )
        try:
            await client.get_registered_fans()
        except InvalidAuth as exception:
            LOGGER.error(exception)
            return {"base": "auth"}
        except (KdkApiError, aiohttp.ClientError, TimeoutError) as exception:
            LOGGER.error(exception)
            return {"base": "connection"}
        except Exception as exception:  # noqa: BLE001
            LOGGER.exception(exception)
            return {"base": "unknown"}
        return {}

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> data_entry_flow.FlowResult:
        """Handle the KDK account rejecting the saved password."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict | None = None
    ) -> data_entry_flow.FlowResult:
        """Ask for the new password."""
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        _errors = {}
        if user_input is not None:
            _errors = await self._test_credentials(
                username=entry.data[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
            )
            if not _errors:
                return self.async_update_reload_and_abort(
                    entry,
                    data={**entry.data, CONF_PASSWORD: user_input[CONF_PASSWORD]},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD,
                        ),
                    ),
                },
            ),
            description_placeholders={CONF_USERNAME: entry.data[CONF_USERNAME]},
            errors=_errors,
        )
