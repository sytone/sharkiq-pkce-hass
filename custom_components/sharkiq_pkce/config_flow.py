"""Config flow for Shark IQ (PKCE).

Two-step flow:

  1. ``user`` -- collect email/password/region and try the normal Auth0
     password grant. If Auth0 says ``requires_verification`` or
     ``too_many_attempts``, we stash the partial state and advance to step 2.
  2. ``pkce`` -- show the user the ``https://login.sharkninja.com/authorize?...``
     URL to open in a browser. The user signs in there, copies the
     resulting ``com.sharkninja.shark://...?code=...`` URL out of the
     address bar (or DevTools), and pastes it back. We exchange the code
     via PKCE, save the Auth0 refresh token, and create the entry.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_REGION, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_create_clientsession

from .const import (
    CONF_AUTH0_REFRESH_TOKEN,
    DOMAIN,
    LOGGER,
    SHARKIQ_REGION_DEFAULT,
    SHARKIQ_REGION_EUROPE,
    SHARKIQ_REGION_OPTIONS,
)
from .sharkiq_lib import AylaApi, SharkIqAuthError, get_ayla_api

CONF_PKCE_REDIRECT = "redirect_url"

USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(
            CONF_REGION, default=SHARKIQ_REGION_DEFAULT
        ): selector.SelectSelector(
            selector.SelectSelectorConfig(
                options=SHARKIQ_REGION_OPTIONS, translation_key="region"
            ),
        ),
    }
)

PKCE_SCHEMA = vol.Schema({vol.Required(CONF_PKCE_REDIRECT): str})


def _extract_code(value: str) -> str | None:
    """Pull the ``code`` query parameter out of a redirect URL (or accept a raw code)."""
    value = (value or "").strip().strip('"').strip("'")
    if not value:
        return None
    if value.startswith(("com.sharkninja.shark://", "http://", "https://")):
        parsed = urlparse(value)
        code = parse_qs(parsed.query).get("code", [None])[0]
        if code is None and parsed.fragment:
            code = parse_qs(parsed.fragment).get("code", [None])[0]
        return code
    # Looks like a bare code value.
    return value


def _make_api(hass: HomeAssistant, data: Mapping[str, Any]) -> AylaApi:
    """Build an AylaApi using HA's shared aiohttp client."""
    websession = async_create_clientsession(
        hass,
        cookie_jar=aiohttp.CookieJar(unsafe=True, quote_cookie=False),
    )
    return get_ayla_api(
        username=data[CONF_USERNAME],
        password=data.get(CONF_PASSWORD, ""),
        websession=websession,
        europe=(data[CONF_REGION] == SHARKIQ_REGION_EUROPE),
    )


async def _try_password_grant(api: AylaApi) -> None:
    """Try the normal password-grant sign-in once, with a timeout."""
    async with asyncio.timeout(15):
        await api.async_sign_in()


class SharkIqPkceConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow for Shark IQ (PKCE)."""

    VERSION = 1

    def __init__(self) -> None:
        self._api: AylaApi | None = None
        self._user_input: dict[str, Any] = {}
        self._pkce_url: str | None = None
        self._pkce_verifier: str | None = None
        self._pkce_reauth_entry_id: str | None = None

    # -------- user step --------

    async def async_step_user(
        self, user_input: dict[str, str] | None = None
    ) -> ConfigFlowResult:
        """Collect credentials and try password-grant sign-in."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_USERNAME].lower())
            if self._pkce_reauth_entry_id is None:
                self._abort_if_unique_id_configured()

            self._user_input = dict(user_input)
            self._api = _make_api(self.hass, user_input)

            try:
                await _try_password_grant(self._api)
            except SharkIqAuthError as err:
                if self._api.requires_interactive_login:
                    LOGGER.info(
                        "Auth0 wants interactive verification -- switching to PKCE step"
                    )
                    return await self.async_step_pkce()
                LOGGER.error("Shark IQ auth error: %s", err)
                errors["base"] = "invalid_auth"
            except (TimeoutError, aiohttp.ClientError) as err:
                LOGGER.error("Shark IQ network error: %s", err)
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                LOGGER.exception("Unexpected Shark IQ auth error")
                errors["base"] = "unknown"
            else:
                return await self._async_finish_entry(self._user_input, self._api)

        return self.async_show_form(
            step_id="user", data_schema=USER_SCHEMA, errors=errors
        )

    # -------- PKCE step --------

    async def async_step_pkce(
        self, user_input: dict[str, str] | None = None
    ) -> ConfigFlowResult:
        """Show the PKCE URL and accept the pasted redirect URL."""
        assert self._api is not None
        errors: dict[str, str] = {}

        if self._pkce_url is None:
            info = self._api.start_interactive_login()
            self._pkce_url = info["url"]
            self._pkce_verifier = info["code_verifier"]

        if user_input is not None:
            code = _extract_code(user_input[CONF_PKCE_REDIRECT])
            if not code:
                errors["base"] = "no_code"
            else:
                try:
                    await self._api.complete_interactive_login(
                        code, code_verifier=self._pkce_verifier
                    )
                except SharkIqAuthError as err:
                    LOGGER.error("PKCE code exchange failed: %s", err)
                    errors["base"] = "invalid_auth"
                except Exception:  # noqa: BLE001
                    LOGGER.exception("Unexpected PKCE error")
                    errors["base"] = "unknown"
                else:
                    return await self._async_finish_entry(self._user_input, self._api)

        return self.async_show_form(
            step_id="pkce",
            data_schema=PKCE_SCHEMA,
            errors=errors,
            description_placeholders={"pkce_url": self._pkce_url or ""},
        )

    # -------- reauth --------

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-auth for an existing entry."""
        self._pkce_reauth_entry_id = self.context.get("entry_id")
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Reauth: same as the user step but updates the existing entry."""
        return await self.async_step_user(user_input)

    # -------- helpers --------

    async def _async_finish_entry(
        self, user_input: Mapping[str, Any], api: AylaApi
    ) -> ConfigFlowResult:
        """Create or update the config entry once auth succeeded."""
        data: dict[str, Any] = dict(user_input)
        if api.auth0_refresh_token:
            data[CONF_AUTH0_REFRESH_TOKEN] = api.auth0_refresh_token

        if self._pkce_reauth_entry_id is not None:
            entry = self.hass.config_entries.async_get_entry(self._pkce_reauth_entry_id)
            if entry is not None:
                self.hass.config_entries.async_update_entry(entry, data=data)
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_create_entry(title=user_input[CONF_USERNAME], data=data)


class CannotConnect(HomeAssistantError):
    """Cannot reach Shark IQ."""


class InvalidAuth(HomeAssistantError):
    """Invalid credentials."""
