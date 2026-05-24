"""Patched, vendored Shark IQ SDK with browser-based PKCE login support.

Vendored from https://github.com/sharkiqlibs/sharkiq with fixes for:

- ``auth0-python>=5`` removed ``auth0.asyncify`` (lazy-imported now).
- ``async_sign_in`` retried on ``requires_verification`` and
  ``429 too_many_attempts``, which caused account lockouts. Both are now
  surfaced via ``api.requires_interactive_login`` instead.
- Added ``start_interactive_login`` / ``complete_interactive_login`` for
  the browser-based PKCE flow used to satisfy Shark's Auth0 captcha.
- Added ``auth0_refresh_token`` so successful logins can be cached and
  Auth0 can be skipped on subsequent restarts.
"""

from .ayla_api import AylaApi, get_ayla_api, Auth0Client
from .exc import (
    SharkIqError,
    SharkIqAuthExpiringError,
    SharkIqNotAuthedError,
    SharkIqAuthError,
    SharkIqReadOnlyPropertyError,
)
from .sharkiq import OperatingModes, PowerModes, Properties, SharkIqVacuum

__version__ = "1.5.1+pkce"

