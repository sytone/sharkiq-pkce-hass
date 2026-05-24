"""Shark IQ (PKCE) Constants."""

from __future__ import annotations

from datetime import timedelta
import logging

from homeassistant.const import Platform

LOGGER = logging.getLogger(__package__)

API_TIMEOUT = 20
PLATFORMS = [Platform.VACUUM]
DOMAIN = "sharkiq_pkce"
SHARK = "Shark"
UPDATE_INTERVAL = timedelta(seconds=30)

ATTR_ROOMS = "rooms"

SHARKIQ_REGION_EUROPE = "europe"
SHARKIQ_REGION_ELSEWHERE = "elsewhere"
SHARKIQ_REGION_DEFAULT = SHARKIQ_REGION_ELSEWHERE
SHARKIQ_REGION_OPTIONS = [SHARKIQ_REGION_EUROPE, SHARKIQ_REGION_ELSEWHERE]

# Config entry keys
CONF_AUTH0_REFRESH_TOKEN = "auth0_refresh_token"
CONF_PKCE_VERIFIER = "_pkce_verifier"
CONF_PKCE_URL = "_pkce_url"
