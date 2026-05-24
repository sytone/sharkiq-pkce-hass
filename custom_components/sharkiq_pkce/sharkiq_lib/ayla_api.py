"""
Simple implementation of the Ayla networks API

Shark IQ robots use the Ayla networks IoT API to communicate with the device.  Documentation can be
found at:
    - https://developer.aylanetworks.com/apibrowser/
    - https://docs.aylanetworks.com/cloud-services/api-browser/
"""

import aiohttp
import base64
import hashlib
import json
import secrets
import urllib.parse
import requests

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from .auth0 import Auth0Client
from .const import (
    DEVICE_URL,
    LOGIN_URL,
    AUTH0_HOST,
    SHARK_APP_ID,
    SHARK_APP_SECRET,
    AUTH0_URL,
    AUTH0_TOKEN_URL,
    AUTH0_CLIENT_ID,
    AUTH0_REDIRECT_URI,
    AUTH0_SCOPES,
    BROWSER_USERAGENT,
    EU_DEVICE_URL,
    EU_AUTH0_HOST,
    EU_LOGIN_URL,
    EU_SHARK_APP_ID,
    EU_SHARK_APP_SECRET,
    EU_AUTH0_URL,
    EU_AUTH0_TOKEN_URL,
    EU_AUTH0_CLIENT_ID
)
from .exc import SharkIqAuthError, SharkIqAuthExpiringError, SharkIqNotAuthedError
from .fallback_auth import FallbackAuth
from .sharkiq import SharkIqVacuum

_session = None


def get_ayla_api(
    username: str,
    password: str,
    websession: Optional[aiohttp.ClientSession] = None,
    europe: bool = False,
    verify_ssl: bool = True,
):
    """
    Get an AylaApi object.

    Args:
        username: The email address of the user.
        password: The password of the user.
        websession: A websession to use for the API.  If None, a new session will be created.
        europe: If True, use the EU login URL and app ID/secret.

    Returns:
        An AylaApi object.
    """
    if europe:
        return AylaApi(
            username,
            password,
            EU_SHARK_APP_ID,
            EU_AUTH0_CLIENT_ID,
            EU_SHARK_APP_SECRET,
            websession=websession,
            europe=europe,
            verify_ssl=verify_ssl,
        )
    else:
        return AylaApi(
            username,
            password,
            SHARK_APP_ID,
            AUTH0_CLIENT_ID,
            SHARK_APP_SECRET,
            websession=websession,
            verify_ssl=verify_ssl,
        )


class AylaApi:
    """Simple Ayla Networks API wrapper."""

    def __init__(
            self,
            email: str,
            password: str,
            app_id: str,
            auth0_client_id: str,
            app_secret: str,
            websession: Optional[aiohttp.ClientSession] = None,
            europe: bool = False,
            verify_ssl: bool = True):
        """
        Initialize the AylaApi object.

        Args:
            email: The email address of the user.
            password: The password of the user.
            app_id: The app ID of the Ayla app.
            app_secret: The app secret of the Ayla app.
            websession: A websession to use for the API.  If None, a new session will be created.
            europe: If True, use the EU login URL and app ID/secret.
        """
        self._email = email
        self._password = password
        self._auth0_id_token = None  # type: Optional[str]
        self._auth0_refresh_token = None  # type: Optional[str]
        self._access_token = None  # type: Optional[str]
        self._refresh_token = None  # type: Optional[str]
        self._auth_expiration = None  # type: Optional[datetime]
        self._is_authed = False  # type: bool
        self._app_id = app_id
        self._auth0_client_id = auth0_client_id
        self._app_secret = app_secret
        self.websession = websession
        self.europe = europe
        # Allow disabling SSL verification if the Ayla host presents a mismatched cert in some environments.
        self.verify_ssl = verify_ssl
        # Flag set when Auth0 requires interactive verification (e.g., captcha/device check).
        self._requires_interactive_login = False
        # Persist a PKCE verifier for interactive flows if needed.
        self._last_pkce_verifier = None  # type: Optional[str]

    async def ensure_session(self) -> aiohttp.ClientSession:
        """
        Ensure that we have an aiohttp ClientSession.
        
        Returns:
            An aiohttp ClientSession.
        """
        if self.websession is None:
            self.websession = aiohttp.ClientSession()
        return self.websession

    @property
    def _login_data(self) -> Dict[str, Dict]:
        """
        Prettily formatted data for the login flow.
        
        Returns:
            A dict containing the login data.
        """
        return {
            "app_id": self._app_id,
            "app_secret": self._app_secret,
            "token": self._auth0_id_token
        }
    
    @property
    def _auth0_login_data(self) -> Dict[str, Dict]:
        """
        Prettily formatted data for the Auth0 login flow.
        
        Returns:
            A dict containing the login data.
        """
        return {
            "grant_type": "password",
            "client_id": self._auth0_client_id,
            "username": self._email,
            "password": self._password,
            "scope": AUTH0_SCOPES
        }
    
    @property
    def _auth0_login_headers(self) -> Dict[str, Dict]:
        """
        Headers for the Auth0 login flow.
        
        Returns:
            A dict containing the headers to send for the Auth0 login flow.
        """
        return {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "dnt": "1",
            "Host": EU_AUTH0_HOST if self.europe else AUTH0_HOST,
            "Origin": EU_AUTH0_URL if self.europe else AUTH0_URL,
            "Priority": "u=1, i",
            "Referrer": EU_AUTH0_URL if self.europe else AUTH0_URL + "/",
            "Sec-Ch-Ua": '"Chrome";v="137", "Chromium";v="137", "Not A;Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"macOS"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Gpc": "1",
            "User-Agent": BROWSER_USERAGENT
        }
    
    @property
    def _ayla_login_headers(self) -> Dict[str, Dict]:
        """
        Headers for the Ayla login flow.
        
        Returns:
            A dict containing the headers to send for the Ayla login flow.
        """
        return {
            "Content-Type": "application/json",
            "User-Agent": BROWSER_USERAGENT
        }

    def _set_credentials(self, status_code: int, login_result: Dict):
        """
        Update the internal credentials store.
        
        Args:
            status_code: The status code of the login response.
            login_result: The result of the login response.
        """
        if status_code == 404:
            raise SharkIqAuthError(login_result["errors"] + " (Confirm app_id and app_secret are correct)")
        elif status_code == 401:
            raise SharkIqAuthError(login_result["errors"])

        self._access_token = login_result["access_token"]
        self._refresh_token = login_result["refresh_token"]
        self._auth_expiration = datetime.now() + timedelta(seconds=login_result["expires_in"])
        self._is_authed = (status_code < 400)

    def _set_id_token(self, status_code: int, login_result: Dict):
        """
        Update the ID token.

        Args:
            status_code: The status code of the login response.
            login_result: The result of the login response.
        """
        if status_code == 401 and login_result.get("error") == "requires_verification":
            self._requires_interactive_login = True
            raise SharkIqAuthError(login_result["error_description"] + ". Auth request flagged for verification.")
        elif status_code == 401:
            raise SharkIqAuthError(login_result["error_description"] + ". Confirm credentials are correct.")
        elif status_code == 400 or status_code == 403:
            raise SharkIqAuthError(login_result["error_description"])

        self._auth0_id_token = login_result["id_token"]

    @staticmethod
    def _generate_pkce_pair() -> Tuple[str, str]:
        """Generate an Auth0 PKCE (verifier, challenge) pair."""
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return verifier, challenge

    def start_interactive_login(self) -> Dict[str, str]:
        """Build an Auth0 authorize URL using PKCE for interactive login.

        Mirrors the parameter set sent by the SharkClean mobile app (``os=ios``,
        ``mobile_shark_app_version``, ``screen_hint=signin``, ``ui_locales=en``)
        because Shark's Auth0 post-login action routes "looks like a real
        first-party request" differently from a bare OAuth client.

        The caller should open ``url`` in a browser, complete the login (and
        any captcha) and pass the resulting ``code`` to
        :meth:`complete_interactive_login`.

        Returns:
            Dict with ``url``, ``state`` and ``code_verifier``. Caller should
            persist ``state``/``code_verifier`` until callback completes.
        """
        verifier, challenge = self._generate_pkce_pair()
        self._last_pkce_verifier = verifier
        state = secrets.token_urlsafe(32)
        auth_domain = EU_AUTH0_URL if self.europe else AUTH0_URL
        client_id = EU_AUTH0_CLIENT_ID if self.europe else AUTH0_CLIENT_ID
        params = {
            "os": "ios",
            "response_type": "code",
            "mobile_shark_app_version": "rn1.01",
            "client_id": client_id,
            "state": state,
            "scope": AUTH0_SCOPES,
            "redirect_uri": AUTH0_REDIRECT_URI,
            "code_challenge": challenge,
            "screen_hint": "signin",
            "code_challenge_method": "S256",
            "ui_locales": "en",
        }
        url = f"{auth_domain}/authorize?{urllib.parse.urlencode(params)}"
        return {"url": url, "state": state, "code_verifier": verifier}

    async def complete_interactive_login(self, code: str, code_verifier: Optional[str] = None):
        """Complete an interactive Auth0 login by exchanging the returned code.

        Args:
            code: The ``code`` query parameter from the ``com.sharkninja.shark://``
                redirect URL the browser produced after sign-in.
            code_verifier: The PKCE verifier returned by
                :meth:`start_interactive_login`. Defaults to the verifier from
                the most recent ``start_interactive_login`` call.
        """
        ayla_client = await self.ensure_session()
        token_url = EU_AUTH0_TOKEN_URL if self.europe else AUTH0_TOKEN_URL
        client_id = EU_AUTH0_CLIENT_ID if self.europe else AUTH0_CLIENT_ID
        verifier = code_verifier or self._last_pkce_verifier
        if verifier is None:
            raise SharkIqAuthError("Missing PKCE verifier for interactive login")
        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code_verifier": verifier,
            "code": code,
            "redirect_uri": AUTH0_REDIRECT_URI,
        }
        async with ayla_client.post(
            token_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            ssl=self.verify_ssl,
            timeout=15,
        ) as resp:
            raw_text = await resp.text()
            try:
                token_json = json.loads(raw_text)
            except Exception:
                token_json = None
            if resp.status >= 400:
                raise SharkIqAuthError(f"Auth0 interactive code exchange failed: {resp.status} {raw_text}")
        if not token_json or "id_token" not in token_json:
            raise SharkIqAuthError("Auth0 interactive response missing id_token")
        self._auth0_id_token = token_json["id_token"]
        if token_json.get("refresh_token"):
            self._auth0_refresh_token = token_json["refresh_token"]
        self._requires_interactive_login = False
        return await self._ayla_token_sign_in(ayla_client)

    @property
    def requires_interactive_login(self) -> bool:
        """True if Auth0 sign-in was flagged as requiring interactive verification."""
        return self._requires_interactive_login

    @property
    def auth0_refresh_token(self) -> Optional[str]:
        """The most recently observed Auth0 refresh token (if any).

        Persisting this across runs lets future sign-ins skip Auth0 entirely.
        """
        return self._auth0_refresh_token

    async def _ayla_token_sign_in(self, ayla_client: aiohttp.ClientSession):
        """Exchange the Auth0 id_token for Ayla credentials."""
        login_data = self._login_data
        login_url = f"{EU_LOGIN_URL if self.europe else LOGIN_URL}/api/v1/token_sign_in"
        async with ayla_client.post(
            login_url,
            json=login_data,
            headers=self._ayla_login_headers,
            ssl=self.verify_ssl,
            timeout=15,
        ) as r2:
            try:
                login_json = await r2.json()
            except Exception:
                login_json = {"errors": await r2.text()}
            self._set_credentials(r2.status, login_json)
        return self._access_token

    async def _auth0_refresh_sign_in(self, ayla_client: aiohttp.ClientSession):
        """Attempt Auth0 refresh_token grant to obtain a new id_token."""
        token_url = EU_AUTH0_TOKEN_URL if self.europe else AUTH0_TOKEN_URL
        client_id = EU_AUTH0_CLIENT_ID if self.europe else AUTH0_CLIENT_ID
        payload = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": self._auth0_refresh_token,
        }
        async with ayla_client.post(
            token_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            ssl=self.verify_ssl,
            timeout=15,
        ) as resp:
            raw_text = await resp.text()
            try:
                token_json = json.loads(raw_text)
            except Exception:
                token_json = None
            if resp.status >= 400:
                raise SharkIqAuthError(f"Auth0 refresh_token grant failed: {resp.status} {raw_text}")
        if not token_json or "id_token" not in token_json:
            raise SharkIqAuthError("Auth0 refresh_token response missing id_token")
        if token_json.get("refresh_token"):
            self._auth0_refresh_token = token_json["refresh_token"]
        self._requires_interactive_login = False
        self._auth0_id_token = token_json["id_token"]

    async def async_set_cookie(self):
        """
        Query Auth0 to set session cookies [required for Auth0 support]
        """
        initial_url = self.gen_fallback_url()
        ayla_client = await self.ensure_session()
        async with ayla_client.get(initial_url, allow_redirects=False, headers=self._auth0_login_headers, ssl=self.verify_ssl) as auth0_resp:
            ayla_client.cookie_jar.update_cookies(auth0_resp.cookies)

    async def _password_grant_sign_in(self, ayla_client: aiohttp.ClientSession):
        """
        Auth0 password grant -> Ayla token_sign_in using aiohttp.
        """
        token_url = EU_AUTH0_TOKEN_URL if self.europe else AUTH0_TOKEN_URL
        payload = {
            "grant_type": "password",
            "client_id": EU_AUTH0_CLIENT_ID if self.europe else AUTH0_CLIENT_ID,
            "username": self._email,
            "password": self._password,
            "scope": AUTH0_SCOPES,
        }
        async with ayla_client.post(
            token_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            ssl=self.verify_ssl,
            timeout=15,
        ) as resp:
            raw_text = await resp.text()
            try:
                auth0_json = json.loads(raw_text)
            except Exception:
                auth0_json = None

            if (
                resp.status == 401
                and isinstance(auth0_json, dict)
                and auth0_json.get("error") == "requires_verification"
            ):
                # Auth0 bot detection wants a human; don't retry, surface a
                # signal so the caller can drive interactive PKCE login.
                self._requires_interactive_login = True
                raise SharkIqAuthError(
                    auth0_json.get(
                        "error_description",
                        "Auth0 requires interactive verification",
                    )
                )
            if (
                resp.status == 429
                or (
                    isinstance(auth0_json, dict)
                    and auth0_json.get("error") == "too_many_attempts"
                )
            ):
                # Account is temporarily locked by Auth0 after too many
                # failed/suspicious attempts. Hitting any other auth endpoint
                # right now would prolong the block; force interactive login.
                self._requires_interactive_login = True
                desc = (
                    auth0_json.get("error_description")
                    if isinstance(auth0_json, dict)
                    else None
                ) or "Auth0 too_many_attempts (account temporarily blocked)"
                raise SharkIqAuthError(desc)
            if resp.status >= 400:
                raise SharkIqAuthError(f"Auth0 password grant failed: {resp.status} {raw_text}")
            if auth0_json is None:
                auth0_json = await resp.json()
        if "id_token" not in auth0_json:
            raise SharkIqAuthError("Auth0 response missing id_token")
        self._requires_interactive_login = False
        self._set_id_token(resp.status, auth0_json)
        if auth0_json.get("refresh_token"):
            self._auth0_refresh_token = auth0_json["refresh_token"]

    async def _legacy_cookie_sign_in(self, ayla_client: aiohttp.ClientSession, force_auth0_sdk: bool = False):
        """
        Legacy Auth0 browser-style flow to obtain id_token.

        Note: each call submits the user's password to Auth0, so repeated
        invocations can lock the account. The wrapping ``async_sign_in`` method
        is responsible for ensuring this is only called when it's safe.
        """
        if force_auth0_sdk:
            # auth0-python >=5 removed asyncify and the SDK fallback path no
            # longer works without it. Even if it did, submitting yet another
            # password attempt after the cookie flow already failed is
            # actively harmful (account lockout), so we no longer retry here.
            try:
                from auth0.authentication import GetToken  # type: ignore
                from auth0.asyncify import asyncify  # type: ignore
            except ImportError as err:
                raise SharkIqAuthError(
                    "Auth0 SDK fallback unavailable (auth0-python>=5 dropped asyncify)."
                ) from err

            AsyncGetToken = asyncify(GetToken)
            get_token = AsyncGetToken(
                EU_AUTH0_HOST if self.europe else AUTH0_HOST,
                EU_AUTH0_CLIENT_ID if self.europe else AUTH0_CLIENT_ID,
            )
            auth_result = await get_token.login_async(
                username=self._email,
                password=self._password,
                grant_type="password",
                scope=AUTH0_SCOPES,
            )
            self._auth0_id_token = auth_result["id_token"]
            return

        auth_result = await Auth0Client.do_auth0_login(
            ayla_client,
            self.europe,
            self._email,
            self._password,
        )
        self._auth0_id_token = auth_result["id_token"]

    async def async_sign_in(self):
        """
        Authenticate to Ayla API asynchronously.

        Tries (in order):
          1. Auth0 refresh-token grant if we already have an Auth0 refresh token.
          2. Auth0 password grant.
          3. The legacy cookie-based Auth0 flow (unless Auth0 has flagged the
             account for interactive verification — in that case we bail out
             with a SharkIqAuthError and ``requires_interactive_login`` set so
             the caller can drive PKCE in a browser instead of risking lockout).
        """
        ayla_client = await self.ensure_session()

        if self._auth0_refresh_token:
            try:
                await self._auth0_refresh_sign_in(ayla_client)
                return await self._ayla_token_sign_in(ayla_client)
            except SharkIqAuthError:
                # Fall through to normal flows.
                pass

        try:
            await self._password_grant_sign_in(ayla_client)
        except SharkIqAuthError:
            if self._requires_interactive_login:
                # Don't retry with the legacy flow — Auth0 will reject it the
                # same way and we risk locking the account after a few attempts.
                raise
            # Genuine failure (bad creds, wrong client id, etc.) — try the
            # legacy browser-style flow once.
            await self._legacy_cookie_sign_in(ayla_client)
        except Exception:
            await self._legacy_cookie_sign_in(ayla_client)

        return await self._ayla_token_sign_in(ayla_client)


    async def async_refresh_auth(self):
        """
        Refresh the authentication synchronously.
        """
        refresh_data = {"user": {"refresh_token": self._refresh_token}}
        ayla_client = await self.ensure_session()
        async with ayla_client.post(f"{EU_LOGIN_URL if self.europe else LOGIN_URL:s}/users/refresh_token.json", json=refresh_data, headers=self._ayla_login_headers) as resp:
            self._set_credentials(resp.status, await resp.json())

    @property
    def sign_out_data(self) -> Dict:
        """
        Payload for the sign_out call.
        
        Returns:
            A dict containing the sign out data.
        """
        return {"user": {"access_token": self._access_token}}

    def _clear_auth(self):
        """
        Clear authentication state.
        """
        self._is_authed = False
        self._access_token = None
        self._refresh_token = None
        self._auth_expiration = None

    async def async_sign_out(self):
        """
        Sign out and invalidate the access token.
        """
        ayla_client = await self.ensure_session()
        async with ayla_client.post(f"{EU_LOGIN_URL if self.europe else LOGIN_URL:s}/users/sign_out.json", json=self.sign_out_data) as _:
            pass
        self._clear_auth()

    def gen_fallback_url(self):
        """
        Generate a URL for the fallback authentication flow.
        
        Returns:
            The URL for the fallback authentication flow.
        """
        return FallbackAuth.GenerateFallbackAuthURL(self.europe)

    @property
    def auth_expiration(self) -> Optional[datetime]:
        """
        Get the time at which the authentication expires.
        
        Returns:
            The time at which the authentication expires.
        """
        if not self._is_authed:
            return None
        elif self._auth_expiration is None:  # This should not happen, but let's be ready if it does...
            raise SharkIqNotAuthedError("Invalid state.  Please reauthorize.")
        else:
            return self._auth_expiration

    @property
    def token_expired(self) -> bool:
        """
        Return true if the token has already expired.
        
        Returns:
            True if the token has already expired.
        """
        if self.auth_expiration is None:
            return True
        return datetime.now() > self.auth_expiration

    @property
    def token_expiring_soon(self) -> bool:
        """
        Return true if the token will expire soon.
        
        Returns:
            True if the token will expire soon.
        """
        if self.auth_expiration is None:
            return True
        return datetime.now() > self.auth_expiration - timedelta(seconds=600)  # Prevent timeout immediately following

    def check_auth(self, raise_expiring_soon=True):
        """
        Confirm authentication status.
        
        Args:
            raise_expiring_soon: Raise an exception if the token will expire soon.

        Raises:
            SharkIqAuthExpiringError: If the token will expire soon.
            SharkIqAuthError: If the token has already expired.
        """
        if not self._access_token or not self._is_authed or self.token_expired:
            self._is_authed = False
            raise SharkIqNotAuthedError()
        elif raise_expiring_soon and self.token_expiring_soon:
            raise SharkIqAuthExpiringError()

    @property
    def auth_header(self) -> Dict[str, str]:
        """
        Get the authorization header.

        Returns:
            The authorization header.
        """
        self.check_auth()
        return {"Authorization": f"auth_token {self._access_token:s}"}

    def _get_headers(self, fn_kwargs) -> Dict[str, str]:
        """
        Extract the headers element from fn_kwargs, removing it if it exists
        and updating with self.auth_header.

        Args:
            fn_kwargs: The kwargs passed to the function.

        Returns:
            The headers.
        """
        try:
            headers = fn_kwargs['headers']
        except KeyError:
            headers = {}
        else:
            del fn_kwargs['headers']
        headers.update(self.auth_header)
        return headers

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make a request to the Ayla API.

        Args:
            method: The HTTP method to use.
            url: The URL to request.
            **kwargs: Additional keyword arguments to pass to requests.

        Returns:
            The response from the request.
        """
        headers = self._get_headers(kwargs)
        return requests.request(method, url, headers=headers, verify=self.verify_ssl, **kwargs)

    async def async_request(self, http_method: str, url: str, **kwargs):
        """
        Make a request to the Ayla API.
        
        Args:
            http_method: The HTTP method to use.
            url: The URL to request.
            **kwargs: Additional keyword arguments to pass to requests.

        Returns:
            The response from the request.
        """
        ayla_client = await self.ensure_session()
        headers = self._get_headers(kwargs)
        result = ayla_client.request(http_method, url, headers=headers, ssl=self.verify_ssl, **kwargs)

        return result

    def list_devices(self) -> List[Dict]:
        """
        List the devices on the account.

        Returns:
            A list of devices.
        """
        resp = self.request("get", f"{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/devices.json")
        devices = resp.json()
        if resp.status_code == 401:
            raise SharkIqAuthError(devices["error"]["message"])
        return [d["device"] for d in devices]

    async def async_list_devices(self) -> List[Dict]:
        """
        List the devices on the account.

        Returns:
            A list of devices.
        """
        async with await self.async_request("get", f"{EU_DEVICE_URL if self.europe else DEVICE_URL:s}/apiv1/devices.json") as resp:
            devices = await resp.json()
            if resp.status == 401:
                raise SharkIqAuthError(devices["error"]["message"])
        return [d["device"] for d in devices]

    def get_devices(self, update: bool = True) -> List[SharkIqVacuum]:
        """
        Get the devices on the account.
        
        Args:
            update: Update the device list if it is out of date.

        Returns:
            A list of devices.
        """
        devices = [SharkIqVacuum(self, d, europe=self.europe) for d in self.list_devices()]
        if update:
            for device in devices:
                device.get_metadata()
                device.update()
        return devices

    async def async_get_devices(self, update: bool = True) -> List[SharkIqVacuum]:
        """
        Get the devices on the account.

        Args:
            update: Update the device list if it is out of date.
        
        Returns:
            A list of devices.
        """
        devices = [SharkIqVacuum(self, d, europe=self.europe) for d in await self.async_list_devices()]
        if update:
            for device in devices:
                await device.async_get_metadata()
                await device.async_update()
        return devices
    
    async def async_close_session(self):
        """
        Close the shared aiohttp ClientSession.

        This should be called when you are finished with the AylaApi object.
        """
        shared_session = self.ensure_session()
        if shared_session is not None:
            shared_session.close()
