# Shark IQ (PKCE) for Home Assistant

A Home Assistant custom integration for Shark IQ robot vacuums that works around the **`requires_verification`** captcha issue blocking the built-in `sharkiq` integration for many US accounts ([home-assistant/core#158700](https://github.com/home-assistant/core/issues/158700), [sharkiqlibs/sharkiq#141](https://github.com/sharkiqlibs/sharkiq/issues/141)).

When Shark's Auth0 service flags your login as suspicious (anything from "new IP" to "we don't like your headers"), it normally bounces the integration and locks the account after a few retries. This integration ships a patched copy of the `sharkiq` library and a config flow that:

1. Tries the normal username/password sign-in **once** (no retry storms ⇒ no lockouts).
2. If Auth0 demands captcha verification, **walks you through a one-time browser PKCE login** and pastes the resulting `com.sharkninja.shark://...?code=...` URL back.
3. Caches the **Auth0 refresh token** in your config entry so HA restarts skip the captcha entirely.

Everything else (vacuum entity, fan speed, locate, return-to-base, `sharkiq_pkce.clean_room` service) mirrors the upstream `sharkiq` integration.

---

## Install via HACS

1. In HACS, open the menu (top-right) → **Custom repositories**.
2. Add `https://github.com/sytone/sharkiq-pkce-hass` as an **Integration**.
3. Find **"Shark IQ (PKCE)"** in HACS and install the latest release.
4. **Restart Home Assistant.**
5. **Settings → Devices & services → Add Integration → "Shark IQ (PKCE)"**.

> The integration's domain is `sharkiq_pkce`, so it coexists with HA's built-in `sharkiq` integration. If you have the built-in one currently failing on the captcha, you can leave it disabled while this one runs.

## Manual install

Copy `custom_components/sharkiq_pkce/` into your Home Assistant `<config>/custom_components/` directory, restart HA, then add the integration from the UI.

---

## First-time setup

1. Enter your SharkClean email, password and region.
2. If Auth0 accepts the password directly, you're done.
3. Otherwise the flow advances to the **PKCE** step and shows you a URL such as:

   ```
   https://login.sharkninja.com/authorize?os=ios&response_type=code&...
   ```

4. Open that URL in a **private/incognito browser window** with **DevTools (F12) → Network → "Preserve log"** enabled.
5. Sign in with your SharkClean credentials. Complete any captcha shown.
6. The browser will appear to "go blank" or jump to `idp.iot-sharkninja.com/...`. In DevTools, look at the most recent `authorize/resume?...` request (status **302**). Copy its **Response Headers → `Location`** value — it'll start with `com.sharkninja.shark://`.
7. Paste that URL into the HA form and submit. The integration exchanges the code, signs in to Ayla, caches the Auth0 refresh token, and creates the vacuum entity.

After this, HA restarts and reloads use the cached refresh token and never need the browser again — until the refresh token eventually expires (typically months) or you change your password.

## Troubleshooting

- **"Please return to the SharkClean App to change the password"** — Auth0 has flagged your account as needing a password reset. Change your password in the SharkClean mobile app, sign in there once, then retry the PKCE step in a fresh incognito window.
- **`429 too_many_attempts`** — Auth0 has temporarily locked your account after too many failed attempts. Check your email for an unblock link, then go straight to the PKCE flow (don't retry password sign-in).
- **PKCE step always errors** — confirm the redirect URL you pasted actually has a `?code=...` query parameter (not just `?state=...&error=...`). The `Location` header from the `authorize/resume` 302 is the most reliable source.

## Acknowledgements

- The base integration is forked from Home Assistant Core's `homeassistant.components.sharkiq` ([source](https://github.com/home-assistant/core/tree/dev/homeassistant/components/sharkiq)).
- The bundled `sharkiq` library is a patched fork of [sharkiqlibs/sharkiq](https://github.com/sharkiqlibs/sharkiq).
- The PKCE pattern is inspired by [TheOneOgre/sharkiq](https://github.com/TheOneOgre/sharkiq).

## License

MIT. See [LICENSE](LICENSE).
