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
