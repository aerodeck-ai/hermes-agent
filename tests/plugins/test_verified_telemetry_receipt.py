from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from hermes_cli.verified_telemetry import VerifiedTelemetryReceipt


def _receipt(**changes):
    fields = dict(runtime="hermes", host="host", seat="seat", profile="profile", person="person", session="s1", phase="p1", trace_class="business", provider="aer", product="none", surface="aer-hermes", usage_authority="gateway")
    fields.update(changes)
    return VerifiedTelemetryReceipt(**fields)


def test_plugin_context_exposes_only_session_bound_content_free_projection():
    manager = PluginManager(verified_telemetry_receipt_resolver=lambda session: _receipt())
    ctx = PluginContext(PluginManifest(name="example"), manager)
    assert ctx.verified_telemetry_receipt("s1") == {"attribution": {"runtime": "hermes", "host": "host", "seat": "seat", "profile": "profile", "person": "person", "session": "s1", "phase": "p1", "trace_class": "business"}, "membership": {"provider": "aer", "product": "none", "surface": "aer-hermes", "profile": "profile"}, "usage_authority": "gateway"}
    assert ctx.verified_telemetry_receipt("other") is None


def test_plugin_context_fails_closed_without_a_host_resolver():
    ctx = PluginContext(PluginManifest(name="example"), PluginManager())
    assert ctx.verified_telemetry_receipt("s1") is None


def test_managed_profile_adapter_binds_the_current_profile_and_can_be_revoked(tmp_path):
    from hermes_cli.managed_profile_telemetry import (
        clear_managed_profile_telemetry_verifier, publish_managed_profile_telemetry_verifier,
        resolver_for_managed_profile,
    )
    owner = object(); seen = []
    def verify(session_id, home):
        seen.append((session_id, home))
        return _receipt(session=session_id)
    publish_managed_profile_telemetry_verifier(owner, verify)
    try:
        resolver = resolver_for_managed_profile(tmp_path / "profile")
        assert resolver is not None and resolver("s1").session == "s1"
        assert seen == [("s1", tmp_path / "profile")]
    finally:
        clear_managed_profile_telemetry_verifier(owner)
    assert resolver_for_managed_profile(tmp_path / "profile") is None
