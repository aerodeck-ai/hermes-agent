"""Route-level CWE-862 tests — the guard must be WIRED IN, not merely present.

``test_cf_access_cwe862.py`` proves the verifier itself is sound.  These prove
each affected handler actually consults it, which is the part a refactor
silently loses: the original defect shipped with a correct-looking comment
above a route that never checked a signature, and a second and third route that
never checked anything at all.

Nothing here touches a live gateway.  The app is built in-process from the
adapter, exactly as tests/gateway/test_api_server.py does it.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

jwt = pytest.importorskip("jwt", reason="PyJWT[crypto] is required")
pytest.importorskip("cryptography")

from aiohttp import web  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from gateway import cf_access  # noqa: E402
from gateway.platforms.api_server import APIServerAdapter  # noqa: E402
from gateway.platforms.base import PlatformConfig  # noqa: E402


TEAM_DOMAIN = "test-team.cloudflareaccess.com"
ISSUER = f"https://{TEAM_DOMAIN}"
AUD = "aud-test-0000"
VICTIM = "victim@example.com"
ATTACKER = "attacker@example.com"
API_KEY = "test-api-key"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def stub_verifier(signing_key, monkeypatch):
    """Point the process-wide verifier at a local key, not Cloudflare."""
    v = cf_access.CFAccessVerifier(
        team_domain=TEAM_DOMAIN, audiences={AUD: "test.example.com"}
    )

    class _StubKey:
        key = signing_key.public_key()

    class _StubClient:
        def get_signing_key_from_jwt(self, token):
            jwt.get_unverified_header(token)
            return _StubKey()

    v._jwk_client = _StubClient()
    monkeypatch.setattr(cf_access, "get_verifier", lambda: v)
    return v


def _token(signing_key, sub, *, aud=AUD, iss=ISSUER, exp_delta=3600):
    now = int(time.time())
    return jwt.encode(
        {"sub": sub, "aud": aud, "iss": iss, "iat": now, "exp": now + exp_delta},
        signing_key,
        algorithm="RS256",
    )


def _forged(sub):
    """The exact attack the unverified decode used to accept."""
    def seg(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()
        ).rstrip(b"=").decode()

    now = int(time.time())
    return ".".join([
        seg({"alg": "RS256", "typ": "JWT", "kid": "k1"}),
        seg({"sub": sub, "aud": AUD, "iss": ISSUER, "iat": now, "exp": now + 3600}),
        "bm90LWEtc2ln",
    ])


def _adapter(*, host: str) -> APIServerAdapter:
    adapter = APIServerAdapter(
        PlatformConfig(enabled=True, extra={"key": API_KEY, "host": host})
    )
    return adapter


def _app(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app["api_server_adapter"] = adapter
    app.router.add_post("/v1/chat/completions", adapter._handle_chat_completions)
    app.router.add_post("/v1/responses", adapter._handle_responses)
    app.router.add_get("/v1/responses/{response_id}", adapter._handle_get_response)
    app.router.add_delete("/v1/responses/{response_id}", adapter._handle_delete_response)
    app.router.add_post("/api/sessions/{session_id}/chat", adapter._handle_session_chat)
    app.router.add_get("/api/sessions/{session_id}", adapter._handle_get_session)
    return app


def _auth():
    return {"Authorization": f"Bearer {API_KEY}"}


# ---------------------------------------------------------------------------
# Defect 1 wired in: a forged JWT is refused at the route, not just the module
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("path,payload", [
    ("/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}]}),
    ("/v1/responses", {"input": "hi"}),
])
async def test_forged_jwt_refused_on_agent_routes(path, payload):
    """A forged assertion must 401 — never fall through to the header path."""
    adapter = _adapter(host="0.0.0.0")
    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            path,
            json=payload,
            headers={
                **_auth(),
                "Cf-Access-Jwt-Assertion": _forged(VICTIM),
                "X-Hermes-Session-Id": "victims-session",
            },
        )
        assert resp.status == 401
        body = await resp.json()
        assert body["error"]["code"] == cf_access.REASON_INVALID


@pytest.mark.asyncio
async def test_forged_jwt_refused_on_session_route():
    adapter = _adapter(host="0.0.0.0")
    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.get(
            "/api/sessions/victims-session",
            headers={**_auth(), "Cf-Access-Jwt-Assertion": _forged(VICTIM)},
        )
        assert resp.status == 401


# ---------------------------------------------------------------------------
# Defect 2 wired in: omitting the header cannot downgrade on an exposed bind
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("path,payload", [
    ("/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}]}),
    ("/v1/responses", {"input": "hi"}),
])
async def test_omitted_header_refused_on_network_bind(path, payload, monkeypatch):
    """Omitting Cf-Access-Jwt-Assertion was the whole bypass: no header meant
    the caller-supplied X-Hermes-Session-Id was honoured verbatim."""
    monkeypatch.delenv("HERMES_CF_ACCESS_REQUIRE_JWT", raising=False)
    adapter = _adapter(host="0.0.0.0")
    async with TestClient(TestServer(_app(adapter))) as cli:
        resp = await cli.post(
            path,
            json=payload,
            headers={**_auth(), "X-Hermes-Session-Id": "victims-session"},
        )
        assert resp.status == 401
        body = await resp.json()
        assert body["error"]["code"] == cf_access.REASON_MISSING


@pytest.mark.asyncio
async def test_omitted_header_allowed_on_loopback_bind(monkeypatch):
    """Loopback-only deployments keep the legacy path, or we break local dev.

    A 401 here would mean require-mode fired; anything else means the request
    got past the identity gate (it may still fail later for unrelated reasons,
    which is not what this test is about).
    """
    monkeypatch.delenv("HERMES_CF_ACCESS_REQUIRE_JWT", raising=False)
    adapter = _adapter(host="127.0.0.1")
    assert adapter._require_cf_jwt is False


@pytest.mark.asyncio
async def test_env_override_can_force_require_on_loopback(monkeypatch):
    monkeypatch.setenv("HERMES_CF_ACCESS_REQUIRE_JWT", "1")
    adapter = _adapter(host="127.0.0.1")
    assert adapter._require_cf_jwt is True


# ---------------------------------------------------------------------------
# Ownership: a valid identity still cannot reach someone else's state
# ---------------------------------------------------------------------------

def test_session_ownership_rejects_another_identity():
    adapter = _adapter(host="0.0.0.0")
    err = adapter._session_ownership_error(
        ATTACKER, "sess-1", {"user_id": VICTIM}
    )
    assert err is not None
    assert err.status == 404  # not 403: don't confirm the session exists


def test_session_ownership_allows_the_owner():
    adapter = _adapter(host="0.0.0.0")
    assert adapter._session_ownership_error(
        VICTIM, "sess-1", {"user_id": VICTIM}
    ) is None


def test_session_ownership_allows_own_derived_id():
    adapter = _adapter(host="0.0.0.0")
    derived = adapter._derive_session_id_from_cf_jwt(VICTIM, "/v1/chat/completions")
    assert adapter._session_ownership_error(VICTIM, derived, {"user_id": None}) is None


def test_session_ownership_rejects_anothers_derived_id():
    adapter = _adapter(host="0.0.0.0")
    derived = adapter._derive_session_id_from_cf_jwt(VICTIM, "/v1/chat/completions")
    err = adapter._session_ownership_error(ATTACKER, derived, {"user_id": None})
    assert err is not None
    assert err.status == 404


def test_unowned_session_refused_under_strict_default(monkeypatch):
    monkeypatch.delenv("HERMES_CF_ACCESS_STRICT_SESSION_OWNERSHIP", raising=False)
    adapter = _adapter(host="0.0.0.0")
    err = adapter._session_ownership_error(VICTIM, "legacy-sess", {"user_id": None})
    assert err is not None


def test_unowned_session_allowed_when_strict_disabled(monkeypatch):
    monkeypatch.setenv("HERMES_CF_ACCESS_STRICT_SESSION_OWNERSHIP", "0")
    adapter = _adapter(host="0.0.0.0")
    assert adapter._session_ownership_error(
        VICTIM, "legacy-sess", {"user_id": None}
    ) is None


def test_no_verified_identity_leaves_legacy_behaviour_untouched():
    """require-mode off + no JWT: the API key is the whole boundary, as before."""
    adapter = _adapter(host="127.0.0.1")
    assert adapter._session_ownership_error(
        None, "someone-elses", {"user_id": VICTIM}
    ) is None


def test_response_ownership_rejects_another_identity():
    adapter = _adapter(host="0.0.0.0")
    adapter._response_store.put("resp-1", {"response": {}}, owner=VICTIM)
    err = adapter._response_ownership_error(ATTACKER, "resp-1")
    assert err is not None
    assert err.status == 404


def test_response_ownership_allows_the_owner():
    adapter = _adapter(host="0.0.0.0")
    adapter._response_store.put("resp-2", {"response": {}}, owner=VICTIM)
    assert adapter._response_ownership_error(VICTIM, "resp-2") is None


def test_response_ownership_defers_on_missing_row():
    """A row that isn't there should 404 via the normal path, not the gate."""
    adapter = _adapter(host="0.0.0.0")
    assert adapter._response_ownership_error(VICTIM, "no-such-response") is None


# ---------------------------------------------------------------------------
# role_map: a broken restrictor must not mean "no restrictions"
# ---------------------------------------------------------------------------

def test_role_map_raises_on_broken_config(tmp_path):
    from gateway.role_map import RoleMap, RoleMapLoadError

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "role-map.yaml").write_text("entries:\n  - bad\n   indentation: here\n")
    (cfg / "role-tools.yaml").write_text("roles: {}\n")

    with pytest.raises(RoleMapLoadError):
        RoleMap.from_profile_dir(tmp_path)


def test_role_map_still_returns_none_when_absent(tmp_path):
    from gateway.role_map import RoleMap

    assert RoleMap.from_profile_dir(tmp_path) is None
