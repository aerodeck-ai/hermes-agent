"""Cloudflare Access JWT verification for the API-server session identity gate.

Background (CWE-862, independent review 2026-09-11 on aerodeck-ai/hermes-agent
PR #4).  Estate commit 13ed1cdd05 added a "server-derived identity" control to
``api_server``: when ``Cf-Access-Jwt-Assertion`` is present, the session id is
derived from the JWT ``sub`` instead of the caller-supplied
``X-Hermes-Session-Id``.  It had two defects, both of which this module exists
to close:

1. The JWT was DECODED but never VERIFIED — no signature, no ``aud``, no
   ``iss``, no ``exp``.  Anyone could forge ``<junk>.<b64 {"sub": "victim"}>.
   <junk>`` and land on the victim's derived session.  That needed only the
   victim's email address, which is *easier* than the original attack it was
   meant to stop (which needed a session id).

2. The guard was fail-open by caller choice: omit the header entirely and you
   got byte-for-byte pre-fix behaviour on the ``X-Hermes-Session-Id`` path.
   There was no "require a JWT" mode.

Everything here fails CLOSED.  A token we cannot fully verify is not an
identity, and ``verify`` returns ``None`` rather than a partially-trusted
claim set.

Configuration (all optional; the defaults are the estate's real values):

  ``HERMES_CF_ACCESS_TEAM_DOMAIN``  CF Access team domain.
  ``HERMES_CF_ACCESS_AUD``          Comma-separated allowed audience tags.
  ``HERMES_CF_ACCESS_JWKS_URL``     Override the derived certs URL.
  ``HERMES_CF_ACCESS_REQUIRE_JWT``  When true, a route that consults identity
                                    REFUSES a request that carries no valid CF
                                    Access JWT.  Default ON for any gateway
                                    bound beyond loopback (see
                                    ``require_jwt_default_for_bind``).
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# The estate's CF Access tenancy.  Sourced from the HD-7 patch
# (hermes_cli/web_server.py, 2026-05-11) which has been verifying these same
# three audiences in production since then.
DEFAULT_TEAM_DOMAIN = "berlai.cloudflareaccess.com"
DEFAULT_AUDIENCES: Dict[str, str] = {
    "ca90f278-a5b1-4d21-9282-76a4a59065ec": "henry-hermes.berl.ai",
    "8f1a4a35-23e8-46f8-a0f6-c136bf26c00d": "mallywork-hermes.berl.ai",
    "3c084b71-9a99-4364-a412-2e43a10cb009": "miranda-hermes.berl.ai",
}

# Cloudflare Access signs with RS256.  Pinning the algorithm list is what stops
# the classic "alg: none" and HMAC-confusion forgeries — never pass the token's
# own header algorithm back to the verifier.
ALLOWED_ALGORITHMS = ("RS256",)

# Small tolerance for clock skew between the CF edge and this host.
LEEWAY_SECONDS = 30

# How long PyJWKClient may reuse a fetched key set.  CF rotates Access signing
# keys roughly every 6 weeks and publishes the new key ahead of use, so six
# hours is comfortably inside the rotation window.
JWKS_CACHE_SECONDS = 21600

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _env_bool(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    val = raw.strip().lower()
    if val in _TRUE:
        return True
    if val in _FALSE:
        return False
    logger.warning("Ignoring unparseable boolean %s=%r", name, raw)
    return None


class CFAccessVerifier:
    """Verifies Cloudflare Access JWTs.  Fails closed on anything unexpected.

    One instance is shared process-wide (see ``get_verifier``).  ``verify`` is
    BLOCKING — the first call for an unseen key id fetches the JWKS over the
    network.  aiohttp handlers must call it via ``asyncio.to_thread``; there is
    an ``averify`` coroutine that does exactly that.
    """

    def __init__(
        self,
        team_domain: Optional[str] = None,
        audiences: Optional[Dict[str, str]] = None,
        jwks_url: Optional[str] = None,
    ) -> None:
        self.team_domain = (
            team_domain
            or os.environ.get("HERMES_CF_ACCESS_TEAM_DOMAIN")
            or DEFAULT_TEAM_DOMAIN
        ).strip()

        if audiences is not None:
            self.audiences = dict(audiences)
        else:
            raw_aud = os.environ.get("HERMES_CF_ACCESS_AUD", "").strip()
            if raw_aud:
                self.audiences = {
                    a.strip(): a.strip() for a in raw_aud.split(",") if a.strip()
                }
            else:
                self.audiences = dict(DEFAULT_AUDIENCES)

        self.issuer = f"https://{self.team_domain}"
        self.jwks_url = (
            jwks_url
            or os.environ.get("HERMES_CF_ACCESS_JWKS_URL")
            or f"{self.issuer}/cdn-cgi/access/certs"
        )

        self._lock = threading.Lock()
        self._jwk_client: Any = None
        self._unavailable_reason: Optional[str] = None

    # -- availability ----------------------------------------------------
    @property
    def available(self) -> bool:
        """True when PyJWT + crypto are importable and config is sane.

        Note this is about our ABILITY to verify, not about whether any given
        token is valid.  When this is False, ``verify`` returns None for every
        token, so callers in require-JWT mode refuse everything — which is the
        correct fail-closed direction for a gateway that cannot check
        signatures.
        """
        return self._ensure_client() is not None

    @property
    def unavailable_reason(self) -> Optional[str]:
        return self._unavailable_reason

    def _ensure_client(self) -> Any:
        if self._jwk_client is not None:
            return self._jwk_client
        with self._lock:
            if self._jwk_client is not None:
                return self._jwk_client
            if not self.audiences:
                self._unavailable_reason = (
                    "no allowed audiences configured "
                    "(set HERMES_CF_ACCESS_AUD)"
                )
                return None
            try:
                from jwt import PyJWKClient
            except Exception as exc:  # pragma: no cover - dependency missing
                self._unavailable_reason = f"PyJWT unavailable: {exc}"
                logger.error(
                    "Cloudflare Access JWT verification is UNAVAILABLE (%s). "
                    "Every CF-JWT identity check will fail closed.",
                    self._unavailable_reason,
                )
                return None
            try:
                self._jwk_client = PyJWKClient(
                    self.jwks_url,
                    cache_keys=True,
                    lifespan=JWKS_CACHE_SECONDS,
                )
            except Exception as exc:  # pragma: no cover - construction failure
                self._unavailable_reason = f"PyJWKClient init failed: {exc}"
                logger.error(
                    "Cloudflare Access JWKS client could not be built (%s).",
                    self._unavailable_reason,
                )
                return None
            return self._jwk_client

    # -- verification ----------------------------------------------------
    def verify(self, token: str) -> Optional[Dict[str, Any]]:
        """Fully verify ``token``; return its claims, or None.

        Checks, in order: a usable JWKS client; the signing key named by the
        token's ``kid``; the RS256 signature; ``iss``; ``aud`` against the
        allowed set; ``exp``/``iat``/``nbf``; and the presence of ``sub``.

        Returns the decoded claims plus a ``hostname`` key naming which
        audience matched, or None if ANY check fails.
        """
        if not token or not isinstance(token, str):
            return None

        client = self._ensure_client()
        if client is None:
            return None

        try:
            import jwt as jwt_mod
        except Exception:  # pragma: no cover - dependency missing
            return None

        try:
            signing_key = client.get_signing_key_from_jwt(token)
        except Exception as exc:
            # Unknown kid, unreachable JWKS, malformed token — all fail closed.
            logger.warning("CF Access JWT: no usable signing key (%s)", exc)
            return None

        # PyJWT checks one audience at a time, so walk the allowed set.  An
        # InvalidAudienceError just means "not this one"; any other error is a
        # real failure and must not be retried against another audience.
        for aud, hostname in self.audiences.items():
            try:
                claims = jwt_mod.decode(
                    token,
                    signing_key.key,
                    algorithms=list(ALLOWED_ALGORITHMS),
                    audience=aud,
                    issuer=self.issuer,
                    leeway=LEEWAY_SECONDS,
                    options={
                        "require": ["exp", "iat", "aud", "iss", "sub"],
                        "verify_signature": True,
                        "verify_exp": True,
                        "verify_iat": True,
                        "verify_nbf": True,
                        "verify_aud": True,
                        "verify_iss": True,
                    },
                )
            except jwt_mod.InvalidAudienceError:
                continue
            except Exception as exc:
                logger.warning("CF Access JWT rejected: %s", exc)
                return None

            sub = claims.get("sub")
            if not sub or not isinstance(sub, str):
                logger.warning("CF Access JWT rejected: no usable 'sub' claim")
                return None
            return {**claims, "hostname": hostname}

        logger.warning("CF Access JWT rejected: audience not in the allowed set")
        return None

    async def averify(self, token: str) -> Optional[Dict[str, Any]]:
        """``verify`` off the event loop (the JWKS fetch does network I/O)."""
        import asyncio

        return await asyncio.to_thread(self.verify, token)

    def verify_sub(self, token: str) -> Optional[str]:
        claims = self.verify(token)
        return claims.get("sub") if claims else None


_verifier: Optional[CFAccessVerifier] = None
_verifier_lock = threading.Lock()


def get_verifier() -> CFAccessVerifier:
    """Process-wide verifier (keeps one JWKS cache rather than one per call)."""
    global _verifier
    if _verifier is None:
        with _verifier_lock:
            if _verifier is None:
                _verifier = CFAccessVerifier()
    return _verifier


def reset_verifier() -> None:
    """Drop the cached verifier.  For tests, and for config reload."""
    global _verifier
    with _verifier_lock:
        _verifier = None


# ---------------------------------------------------------------------------
# require-JWT mode
# ---------------------------------------------------------------------------

def require_jwt_enabled(network_accessible: bool) -> bool:
    """Whether a missing CF JWT must be refused rather than downgraded.

    ``HERMES_CF_ACCESS_REQUIRE_JWT`` wins when set.  Otherwise it defaults to
    ``network_accessible`` — ON for any gateway reachable beyond loopback.
    A gateway on 0.0.0.0 is exposed to every network the host sits on (on
    aerodeck that was the whole tailnet plus the docker bridge), so the
    caller-controlled header path must not be available there as a silent
    downgrade.  Loopback-only binds keep the old behaviour so local
    development and the on-box MCP callers are not broken.

    Callers pass ``gateway.platforms.base.is_network_accessible(bind_host)``,
    which already resolves hostnames and fails closed on DNS failure.
    """
    override = _env_bool("HERMES_CF_ACCESS_REQUIRE_JWT")
    if override is not None:
        return override
    return bool(network_accessible)


# ---------------------------------------------------------------------------
# The gate the routes actually call
# ---------------------------------------------------------------------------

#: Reasons ``resolve_identity`` can refuse, for the caller's error payload.
REASON_MISSING = "cf_access_jwt_required"
REASON_INVALID = "cf_access_jwt_invalid"


def resolve_identity(
    raw_jwt: Optional[str],
    *,
    require: bool,
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a caller identity from the raw ``Cf-Access-Jwt-Assertion`` value.

    Returns ``(sub, refusal_reason)``.  Exactly one is ever non-None, except
    for the "no JWT, not required" case which returns ``(None, None)`` meaning
    "no identity, carry on with the legacy path".

    The three cases that matter:

      * a VALID token           -> (sub, None)
      * a token that is PRESENT but does not verify -> (None, REASON_INVALID),
        ALWAYS, even when ``require`` is False.  A bad token is an attack
        signal; silently falling through to the caller-controlled header path
        is exactly the fail-open defect this replaces.
      * NO token                -> (None, REASON_MISSING) when ``require``,
        else (None, None).
    """
    token = (raw_jwt or "").strip()
    if not token:
        return (None, REASON_MISSING if require else None)

    sub = get_verifier().verify_sub(token)
    if sub:
        return (sub, None)
    return (None, REASON_INVALID)


async def aresolve_identity(
    raw_jwt: Optional[str],
    *,
    require: bool,
) -> Tuple[Optional[str], Optional[str]]:
    """``resolve_identity`` off the event loop."""
    import asyncio

    token = (raw_jwt or "").strip()
    if not token:
        return (None, REASON_MISSING if require else None)
    sub = await asyncio.to_thread(get_verifier().verify_sub, token)
    if sub:
        return (sub, None)
    return (None, REASON_INVALID)
