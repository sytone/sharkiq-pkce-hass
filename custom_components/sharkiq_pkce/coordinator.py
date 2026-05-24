"""Data update coordinator for Shark IQ (PKCE) vacuums."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import API_TIMEOUT, CONF_AUTH0_REFRESH_TOKEN, DOMAIN, LOGGER, UPDATE_INTERVAL
from .sharkiq_lib import (
    AylaApi,
    SharkIqAuthError,
    SharkIqAuthExpiringError,
    SharkIqNotAuthedError,
    SharkIqVacuum,
)

type SharkIqConfigEntry = ConfigEntry["SharkIqUpdateCoordinator"]


class SharkIqUpdateCoordinator(DataUpdateCoordinator[bool]):
    """Wrapper for periodic Shark IQ data updates."""

    config_entry: SharkIqConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: SharkIqConfigEntry,
        ayla_api: AylaApi,
        shark_vacs: list[SharkIqVacuum],
    ) -> None:
        """Initialise the coordinator."""
        self.ayla_api = ayla_api
        self.shark_vacs: dict[str, SharkIqVacuum] = {
            sharkiq.serial_number: sharkiq for sharkiq in shark_vacs
        }
        self._online_dsns: set[str] = set()

        super().__init__(
            hass,
            LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )

    @property
    def online_dsns(self) -> set[str]:
        """Return the set of online vacuum DSNs."""
        return self._online_dsns

    def device_is_online(self, dsn: str) -> bool:
        """Return whether a given vacuum DSN is online."""
        return dsn in self._online_dsns

    @staticmethod
    async def _async_update_vacuum(sharkiq: SharkIqVacuum) -> None:
        """Update one vacuum's data with a timeout."""
        async with asyncio.timeout(API_TIMEOUT):
            await sharkiq.async_update()

    def _persist_refresh_token_if_changed(self) -> None:
        """If the Auth0 refresh token rotated, save it back to the config entry."""
        current = self.ayla_api.auth0_refresh_token
        if not current:
            return
        stored = self.config_entry.data.get(CONF_AUTH0_REFRESH_TOKEN)
        if stored == current:
            return
        new_data = {**self.config_entry.data, CONF_AUTH0_REFRESH_TOKEN: current}
        self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)

    async def _async_update_data(self) -> bool:
        """Refresh data for every online vacuum."""
        try:
            if (
                self.ayla_api.token_expiring_soon
                or datetime.now()
                > self.ayla_api.auth_expiration - timedelta(seconds=600)
            ):
                await self.ayla_api.async_refresh_auth()
                self._persist_refresh_token_if_changed()

            all_vacuums = await self.ayla_api.async_list_devices()
            self._online_dsns = {
                v["dsn"]
                for v in all_vacuums
                if v["connection_status"] == "Online" and v["dsn"] in self.shark_vacs
            }

            online_vacs = (self.shark_vacs[dsn] for dsn in self.online_dsns)
            await asyncio.gather(*(self._async_update_vacuum(v) for v in online_vacs))
        except (
            SharkIqAuthError,
            SharkIqNotAuthedError,
            SharkIqAuthExpiringError,
        ) as err:
            LOGGER.debug("Bad auth state -- requesting reauth", exc_info=err)
            raise ConfigEntryAuthFailed from err
        except Exception as err:  # noqa: BLE001
            LOGGER.exception("Unexpected error updating SharkIQ")
            raise UpdateFailed(err) from err

        return True
