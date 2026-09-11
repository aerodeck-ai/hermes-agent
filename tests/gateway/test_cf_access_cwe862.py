"""CWE-862 session-smuggling regression tests.

These pin the two defects an independent review found in the estate's
"server-derived identity" control (aerodeck-ai/hermes-agent PR #4, 2026-09-11),
both inherited from estate commit 13ed1cdd05:

  1. The CF Access JWT was decoded but never verified — no signature, no aud,
     no iss, no exp. A caller could forge ``<junk>.<b64 {"sub": victim}>.<junk>``
     and land on the victim's derived session, needing only an email address.

  2. The guard was fail-open by caller choice: OMIT the header entirely and you
     got byte-for-byte pre-fix behaviour on the caller-controlled
     ``X-Hermes-Session-Id`` path. There was no require-JWT mode.

Everything here runs against a locally generated RSA key acting as the JWKS —
no network, and deliberately no traffic at any live gateway.
"""

from __future__ import annotations

import json
import time

import pytest

jwt = pytest.importorskip("jwt", reason="PyJWT[crypto] is required")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from gateway import cf_access  # noqa: E402


TEAM_DOMAIN = "test-team.cloudflareaccess.com"
ISSUER = f"https://{TEAM_DOMAIN}"
GOOD_AUD = "aud-good-0000"
OTHER_AUD = "aud-other-1111"
VICTIM = "henry@example.com"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


@pytest.fixture
def verifier(keypair, monkeypatch):
    """A verifier whose JWKS lookup returns our local public key."""
    _, public_key = keypair

    v = cf_access.CFAccessVerifier(
        team_domain=TEAM_DOMAIN,
        audiences={GOOD_AUD: "test-hermes.example.com"},
    )

    class _StubKey:
        key = public_key

    class _StubClient:
        def get_signing_key_from_jwt(self, token):
            # Mimic PyJWKClient: a token we cannot even parse has no key.
            jwt.get_unverified_header(token)
            return _StubKey()

    v._jwk_client = _StubClient()
    return v


def _sign(keypair, claims, *, aud=GOOD_AUD, iss=ISSUER, exp_delta=3600):
    private_key, _ = keypair
    now = int(time.time())
    payload = {
        "sub": VICTIM,
        "aud": aud,
        "iss": iss,
        "iat": now,
        "exp": now + exp_delta,
        **claims,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


# ---------------------------------------------------------------------------
# Defect 1 — the JWT is now actually verified
# ---------------------------------------------------------------------------

def test_valid_jwt_yields_its_sub(keypair, verifier):
    token = _sign(keypair, {})
    assert verifier.verify_sub(token) == VICTIM


def test_forged_unsigned_jwt_is_refused(verifier):
    """THE original attack: three base64 segments, no real signature.

    This is the exact shape the old unverified decode accepted. It needed only
    the victim's email — easier than the session-id attack it was meant to
    stop.
    """
    import base64

    def seg(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    forged = ".".join([
        seg({"alg": "RS256", "typ": "JWT", "kid": "whatever"}),
        seg({"sub": VICTIM, "aud": GOOD_AUD, "iss": ISSUER,
             "iat": now, "exp": now + 3600}),
        "bm90LWEtc2lnbmF0dXJl",  # "not-a-signature"
    ])
    assert verifier.verify_sub(forged) is None


def test_jwt_signed_by_the_wrong_key_is_refused(verifier):
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    token = jwt.encode(
        {"sub": VICTIM, "aud": GOOD_AUD, "iss": ISSUER,
         "iat": now, "exp": now + 3600},
        attacker_key,
        algorithm="RS256",
    )
    assert verifier.verify_sub(token) is None


def test_alg_none_is_refused(verifier):
    now = int(time.time())
    token = jwt.encode(
        {"sub": VICTIM, "aud": GOOD_AUD, "iss": ISSUER,
         "iat": now, "exp": now + 3600},
        key="",
        algorithm="none",
    )
    assert verifier.verify_sub(token) is None


def test_wrong_audience_is_refused(keypair, verifier):
    token = _sign(keypair, {}, aud=OTHER_AUD)
    assert verifier.verify_sub(token) is None


def test_wrong_issuer_is_refused(keypair, verifier):
    token = _sign(keypair, {}, iss="https://evil.cloudflareaccess.com")
    assert verifier.verify_sub(token) is None


def test_expired_token_is_refused(keypair, verifier):
    token = _sign(keypair, {}, exp_delta=-7200)
    assert verifier.verify_sub(token) is None


def test_missing_sub_is_refused(keypair, verifier):
    token = _sign(keypair, {"sub": None})
    assert verifier.verify_sub(token) is None


def test_garbage_is_refused(verifier):
    for junk in ("", "   ", "not-a-jwt", "a.b", "a.b.c.d"):
        assert verifier.verify_sub(junk) is None


def test_verification_fails_closed_when_unavailable(monkeypatch):
    """No usable JWKS client means no identity — never a trusted decode."""
    v = cf_access.CFAccessVerifier(team_domain=TEAM_DOMAIN, audiences={})
    assert v.available is False
    assert v.verify_sub("anything") is None


# ---------------------------------------------------------------------------
# Defect 2 — require-JWT mode, and no silent downgrade
# ---------------------------------------------------------------------------

def _patch_singleton(monkeypatch, verifier):
    monkeypatch.setattr(cf_access, "get_verifier", lambda: verifier)


def test_missing_header_is_refused_when_required(monkeypatch, verifier):
    _patch_singleton(monkeypatch, verifier)
    sub, reason = cf_access.resolve_identity(None, require=True)
    assert sub is None
    assert reason == cf_access.REASON_MISSING


def test_missing_header_falls_through_when_not_required(monkeypatch, verifier):
    _patch_singleton(monkeypatch, verifier)
    sub, reason = cf_access.resolve_identity(None, require=False)
    assert (sub, reason) == (None, None)


def test_invalid_header_is_refused_even_when_not_required(monkeypatch, verifier):
    """A bad token must NEVER downgrade to the caller-controlled header path.

    This is the fail-open hole: an attacker who supplies a broken JWT must not
    be handed the same treatment as someone who supplied none.
    """
    _patch_singleton(monkeypatch, verifier)
    sub, reason = cf_access.resolve_identity("not-a-jwt", require=False)
    assert sub is None
    assert reason == cf_access.REASON_INVALID


def test_valid_header_resolves_regardless_of_require(monkeypatch, keypair, verifier):
    _patch_singleton(monkeypatch, verifier)
    token = _sign(keypair, {})
    for require in (True, False):
        sub, reason = cf_access.resolve_identity(token, require=require)
        assert (sub, reason) == (VICTIM, None)


# ---------------------------------------------------------------------------
# require-JWT defaults by bind exposure
# ---------------------------------------------------------------------------

def test_require_defaults_on_for_network_accessible_bind(monkeypatch):
    monkeypatch.delenv("HERMES_CF_ACCESS_REQUIRE_JWT", raising=False)
    assert cf_access.require_jwt_enabled(True) is True


def test_require_defaults_off_for_loopback_bind(monkeypatch):
    monkeypatch.delenv("HERMES_CF_ACCESS_REQUIRE_JWT", raising=False)
    assert cf_access.require_jwt_enabled(False) is False


@pytest.mark.parametrize("raw,expected", [("1", True), ("0", False),
                                          ("true", True), ("off", False)])
def test_env_override_wins(monkeypatch, raw, expected):
    monkeypatch.setenv("HERMES_CF_ACCESS_REQUIRE_JWT", raw)
    # Set against the bind default that would give the opposite answer.
    assert cf_access.require_jwt_enabled(not expected) is expected


def test_estate_defaults_are_the_three_known_audiences(monkeypatch):
    monkeypatch.delenv("HERMES_CF_ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("HERMES_CF_ACCESS_AUD", raising=False)
    v = cf_access.CFAccessVerifier()
    assert v.team_domain == "berlai.cloudflareaccess.com"
    assert set(v.audiences.values()) == {
        "henry-hermes.berl.ai",
        "mallywork-hermes.berl.ai",
        "miranda-hermes.berl.ai",
    }
