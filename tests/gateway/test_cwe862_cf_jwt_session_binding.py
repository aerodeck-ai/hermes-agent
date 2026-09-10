"""CWE-862 regression: a CF Access JWT must bind session identity server-side.

Estate fix 13ed1cdd05, rebased onto v2026.9.7 (lane-1018-hermes-upgrade). Upstream
extracted the chat-completions handler into
``gateway/platforms/api_server_openai_routes.py``, so the guard moved with it. These
tests pin the security property at the new site rather than the old one.

The hole: a caller holding the Bearer token for profile A sends
``X-Hermes-Session-Id: <profile-B-session>`` and reads profile B's history. When CF
Access is in the path the JWT ``sub`` is server-supplied and non-spoofable, so the
session id is derived from it and the caller-supplied header is ignored.
"""

import re

from gateway.platforms.api_server import APIServerAdapter


class _FakeRequest:
    def __init__(self, headers=None, path="/v1/chat/completions"):
        self.headers = headers or {}
        self.path = path


def _derive(cf_sub, route="/v1/chat/completions"):
    return APIServerAdapter._derive_session_id_from_cf_jwt(
        APIServerAdapter, cf_sub, route)


class TestDerivedSessionIdIsServerControlled:
    def test_same_sub_and_route_is_stable(self):
        """A given identity maps to one session id, so continuation works."""
        assert _derive("henry@example.com") == _derive("henry@example.com")

    def test_different_subs_never_collide(self):
        """Two tenants must not land on the same session id."""
        assert _derive("henry@example.com") != _derive("mallory@example.com")

    def test_route_is_part_of_the_identity(self):
        """The same person on a different route gets a different session."""
        a = _derive("henry@example.com", "/v1/chat/completions")
        b = _derive("henry@example.com", "/v1/responses")
        assert a != b

    def test_derived_id_cannot_escape_its_directory(self):
        """Session ids are interpolated into on-disk filenames.

        The property that matters is containment, not the absence of a dot pair:
        the sanitiser maps every separator and control character to ``_``, so a
        traversal payload in the JWT ``sub`` collapses into one flat component.
        """
        import os

        for nasty in ("../../etc/passwd", "..", "../" * 8 + "etc/shadow",
                      "a/../../b", "x\r\n\x00y"):
            derived = _derive(nasty)
            assert re.match(r"^api_server:[A-Za-z0-9@._+-]*:[a-f0-9]{8}$", derived), derived
            # No separator or control character survives sanitisation.
            for bad in ("/", "\\", "\r", "\n", "\x00", ";"):
                assert bad not in derived, f"{bad!r} survived into {derived!r}"
            # One flat path component that resolves inside its parent.
            assert os.path.basename(derived) == derived
            assert os.path.normpath(os.path.join("/var/lib/hermes", derived)) == \
                f"/var/lib/hermes/{derived}"


class TestDerivedIdsBypassTheCallerSuppliedGuard:
    """Documents a real asymmetry found while rebasing onto v2026.9.7.

    Upstream screens CALLER-supplied session ids with ``_is_path_unsafe`` and
    rejects a match. The estate's SERVER-derived ids skip that screen, and a
    traversal-shaped JWT ``sub`` produces an id the screen would reject — the
    literal ``..`` component survives even though every separator is stripped.

    This is not exploitable: containment is proven above. But if a later change
    ever routes a derived id through that guard, sessions for such identities
    would start 400-ing. Pinned so the behaviour is a decision, not a surprise.
    """

    def test_derived_id_can_trip_the_caller_supplied_screen(self):
        from gateway.session import _is_path_unsafe

        derived = _derive("../../etc/passwd")
        assert _is_path_unsafe(derived) is True
        # ...while remaining contained, which is why it is safe today.
        import os
        assert os.path.basename(derived) == derived

    def test_ordinary_identities_are_unaffected(self):
        from gateway.session import _is_path_unsafe

        for sub in ("henry@example.com", "user_123", "a.b+c@corp.co.uk"):
            assert _is_path_unsafe(_derive(sub)) is False


class TestCfJwtSubExtraction:
    def test_absent_header_yields_none(self):
        """No CF Access in front: fall through to the API-key path."""
        assert APIServerAdapter._extract_cf_jwt_sub(_FakeRequest()) is None

    def test_malformed_jwt_yields_none_and_does_not_raise(self):
        """A junk assertion must not become an identity or crash the request."""
        for junk in ("", "not-a-jwt", "a.b", "a.b.c.d", "..", "x" * 4096):
            req = _FakeRequest({"Cf-Access-Jwt-Assertion": junk})
            assert APIServerAdapter._extract_cf_jwt_sub(req) is None


class TestGuardIsWiredAtTheRelocatedSite:
    """The fix is only real if it sits in the handler upstream actually calls."""

    def test_openai_routes_derives_before_trusting_the_header(self):
        import inspect
        from gateway.platforms import api_server_openai_routes as mod

        src = inspect.getsource(mod)
        assert "cf_sub = self._extract_cf_jwt_sub(request)" in src
        # The CF-JWT branch must be tested BEFORE the caller-supplied header is
        # honoured, or the header still wins.
        assert src.index("if cf_sub:") < src.index("elif provided_session_id:")

    def test_adapter_exposes_the_helpers_to_the_mixin(self):
        """The helpers live in api_server.py; the handler is in the mixin."""
        assert hasattr(APIServerAdapter, "_extract_cf_jwt_sub")
        assert hasattr(APIServerAdapter, "_derive_session_id_from_cf_jwt")
