"""Shark IQ (PKCE) integration setup."""

from __future__ import annotations

import asyncio
from contextlib import suppress

import aiohttp

from homeassistant import exceptions
from homeassistant.const import CONF_PASSWORD, CONF_REGION, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.typing import ConfigType

from .const import (
    API_TIMEOUT,
    CONF_AUTH0_REFRESH_TOKEN,
    DOMAIN,
    LOGGER,
    PLATFORMS,
    SHARKIQ_REGION_DEFAULT,
    SHARKIQ_REGION_EUROPE,
)
from .coordinator import SharkIqConfigEntry, SharkIqUpdateCoordinator
from .services import async_setup_services
from .sharkiq_lib import (
    AylaApi,
    SharkIqAuthError,
    SharkIqAuthExpiringError,
    SharkIqNotAuthedError,
    get_ayla_api,
)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


class CannotConnect(exceptions.HomeAssistantError):
    """Cannot reach Shark IQ."""


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register integration-level services."""
    async_setup_services(hass)
    return True


async def _async_build_api(hass: HomeAssistant, entry: SharkIqConfigEntry) -> AylaApi:
    """Construct an AylaApi instance, restoring a cached Auth0 refresh token if any."""
    websession = async_create_clientsession(
        hass,
        cookie_jar=aiohttp.CookieJar(unsafe=True, quote_cookie=False),
    )
    api = get_ayla_api(
        username=entry.data[CONF_USERNAME],
        password=entry.data.get(CONF_PASSWORD, ""),
        websession=websession,
        europe=(entry.data[CONF_REGION] == SHARKIQ_REGION_EUROPE),
    )
    cached = entry.data.get(CONF_AUTH0_REFRESH_TOKEN)
    if cached:
        # Documented internal hook -- restores the cached refresh token so
        # async_sign_in() takes the refresh path and skips Auth0's captcha.
        api._auth0_refresh_token = cached  # noqa: SLF001
    return api


async def _async_connect_or_timeout(api: AylaApi) -> bool:
    """Authenticate to Ayla; raise reauth on a hard auth error."""
    try:
        async with asyncio.timeout(API_TIMEOUT):
            await api.async_sign_in()
    except SharkIqAuthError as err:
        if api.requires_interactive_login:
            LOGGER.warning(
                "Auth0 demands interactive verification; triggering reauth flow"
            )
            raise exceptions.ConfigEntryAuthFailed from err
        LOGGER.error("Shark IQ auth error: %s", err)
        raise exceptions.ConfigEntryAuthFailed from err
    except TimeoutError as err:
        raise CannotConnect from err
    return True


async def async_setup_entry(
    hass: HomeAssistant, entry: SharkIqConfigEntry
) -> bool:
    """Set up a Shark IQ (PKCE) config entry."""
    if CONF_REGION not in entry.data:
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, CONF_REGION: SHARKIQ_REGION_DEFAULT}
        )

    api = await _async_build_api(hass, entry)

    try:
        await _async_connect_or_timeout(api)
    except CannotConnect as err:
        raise exceptions.ConfigEntryNotReady from err

    # Persist any (rotated) Auth0 refresh token immediately so the next
    # restart skips Auth0 entirely.
    current = api.auth0_refresh_token
    if current and current != entry.data.get(CONF_AUTH0_REFRESH_TOKEN):
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, CONF_AUTH0_REFRESH_TOKEN: current}
        )

    shark_vacs = await api.async_get_devices(False)
    LOGGER.debug(
        "Found %d Shark IQ device(s): %s",
        len(shark_vacs),
        ", ".join(d.name for d in shark_vacs),
    )

    coordinator = SharkIqUpdateCoordinator(hass, entry, api, shark_vacs)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_disconnect_or_timeout(coordinator: SharkIqUpdateCoordinator) -> None:
    """Best-effort sign out from Ayla."""
    async with asyncio.timeout(5):
        with suppress(
            SharkIqAuthError, SharkIqAuthExpiringError, SharkIqNotAuthedError
        ):
            await coordinator.ayla_api.async_sign_out()


async def async_update_options(hass: HomeAssistant, entry: SharkIqConfigEntry) -> None:
    """Reload the config entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: SharkIqConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        with suppress(SharkIqAuthError):
            await _async_disconnect_or_timeout(entry.runtime_data)
    return unload_ok
