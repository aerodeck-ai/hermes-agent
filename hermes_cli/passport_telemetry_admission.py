"""Core verification of C1's signed telemetry-admission frame.

The frame is produced by the Passport authority and verified before an exporter
can receive content.  This module deliberately has no PluginManager, callback,
or ContextVar seam: a portable plugin cannot publish, replace, or manufacture
the admission authority.  The managed C1 adapter supplies its pinned public
key and the native gateway context when an approved runtime integration lands.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


_RECEIPT_SCHEMA = "aerodeck.passport-verification-receipt/v2"
_ACTION = _CAPABILITY = "langfuse.final-export.emit"
_AUDIENCE = "langfuse.final-export"
_BOUNDARY_KIND = "langfuse-final-export/v2"
_RUNTIME_MEMBERSHIP = ("aer", "hermes", "aer-hermes")
_USAGE_AUTHORITIES = frozenset(("gateway", "direct-provider"))
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_ZERO_USAGE = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cached_tokens": 0}
_METADATA_FIELDS = frozenset(("model", "provider", "policy_version"))
_CONTENT_FIELDS = frozenset((
    "body", "content", "tool", "tools", "tool_calls", "function", "functions", "function_call",
    "media", "image", "image_url", "audio", "video", "file", "file_url",
))


class TelemetryAdmissionDenied(ValueError):
    """The signed frame is not an export authority for this native turn."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise TelemetryAdmissionDenied(f"invalid_{name}")
    return value


def _payload_sha256(body: str) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json({"body": body}).encode()).hexdigest()


def _signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise TelemetryAdmissionDenied("signature_invalid")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise TelemetryAdmissionDenied("signature_invalid") from exc


def _identity(context: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(context, Mapping):
        raise TelemetryAdmissionDenied("native_context_missing")
    return {name: _safe_id(context.get(name), name) for name in (
        "profile_id", "session_id", "native_turn_id", "host_id", "workload_id", "human_owner",
    )}


def _classification(context: Mapping[str, Any]) -> str:
    # An unknown classification is intentionally no more permissive than LIFE.
    value = context.get("classification") if isinstance(context, Mapping) else None
    return value if value == "business" else "metadata-only"


def _canonical_host(host: str) -> str:
    return {"henrys-macbook-pro": "macbook", "henrys-mac-mini": "macmini"}.get(host, host)


def _trace_ids(identity: Mapping[str, str]) -> tuple[str, str, str]:
    seed = "|".join(("v1", "hermes", _canonical_host(identity["host_id"]), identity["workload_id"],
                     identity["profile_id"], identity["human_owner"], identity["session_id"]))
    trace_id = hashlib.sha256(seed.encode()).hexdigest()[:32]
    span_id = hashlib.sha256((seed + "|ExecutionStart").encode()).hexdigest()[:16]
    export_id = "pfe_" + hashlib.sha256(
        (trace_id + "|" + identity["native_turn_id"]).encode()
    ).hexdigest()[:32]
    return trace_id, span_id, export_id


def _verify_signature(frame: Mapping[str, Any], issuer_public_key_pem: bytes | str) -> None:
    if not isinstance(issuer_public_key_pem, (bytes, str)):
        raise TelemetryAdmissionDenied("issuer_key_invalid")
    signed = dict(frame)
    signature = signed.pop("issuer_signature", None)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key = serialization.load_pem_public_key(
            issuer_public_key_pem if isinstance(issuer_public_key_pem, bytes) else issuer_public_key_pem.encode()
        )
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("expected Ed25519")
        key.verify(_signature(signature), _canonical_json(signed).encode())
    except TelemetryAdmissionDenied:
        raise
    except Exception as exc:
        raise TelemetryAdmissionDenied("signature_invalid") from exc


def _contains_content(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(name in _CONTENT_FIELDS or _contains_content(item) for name, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_content(item) for item in value)
    return False


def _verify_frame(frame: Mapping[str, Any], identity: Mapping[str, str], body: str, now: int) -> str:
    if not isinstance(frame, Mapping) or frame.get("schema") != _RECEIPT_SCHEMA:
        raise TelemetryAdmissionDenied("schema_unsupported")
    if _contains_content(frame):
        raise TelemetryAdmissionDenied("frame_content_forbidden")
    if frame.get("signature_algorithm") != "Ed25519":
        raise TelemetryAdmissionDenied("signature_algorithm_unsupported")
    _safe_id(frame.get("passport_issuer"), "passport_issuer")
    _safe_id(frame.get("receipt_issuer_kid"), "receipt_issuer_kid")
    if not isinstance(frame.get("expires_at"), int) or frame["expires_at"] <= now:
        raise TelemetryAdmissionDenied("receipt_expired")
    if (frame.get("policy_decision") != "ALLOW" or frame.get("policy_action") != _ACTION
            or _AUDIENCE not in frame.get("audiences", ()) or _CAPABILITY not in frame.get("capabilities", ())):
        raise TelemetryAdmissionDenied("scope_denied")
    actor, claims = frame.get("permitted_actor"), frame.get("passport_claims")
    if (frame.get("permitted_domain") != "business" or frame.get("permitted_tenant") != "business"
            or not isinstance(actor, Mapping)
            or not isinstance(claims, Mapping)
            or any(actor.get(name) != value or claims.get(name) != value for name, value in identity.items())
            or claims.get("estate") != "business"):
        raise TelemetryAdmissionDenied("native_binding_mismatch")
    membership = frame.get("verified_runtime_membership")
    if (not isinstance(membership, Mapping)
            or tuple(membership.get(name) for name in ("provider", "runtime", "surface")) != _RUNTIME_MEMBERSHIP
            or membership.get("profile_id") != identity["profile_id"]
            or frame.get("verified_product") != "none"):
        raise TelemetryAdmissionDenied("runtime_membership_denied")
    authority = frame.get("usage_authority")
    if authority not in _USAGE_AUTHORITIES:
        raise TelemetryAdmissionDenied("usage_authority_invalid")
    expected_context = {
        "kind": _BOUNDARY_KIND, "native_turn_id": identity["native_turn_id"],
        "surface": "aer-hermes", "payload_sha256": _payload_sha256(body),
    }
    if frame.get("boundary_context") != expected_context:
        raise TelemetryAdmissionDenied("boundary_mismatch")
    return authority


def _metadata(value: Any) -> dict[str, str | int | bool]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str | int | bool] = {}
    for name in _METADATA_FIELDS:
        item = value.get(name)
        if (isinstance(item, (bool, int))
                or isinstance(item, str) and len(item) <= 200 and "\n" not in item):
            result[name] = item
    return result


@dataclass(frozen=True)
class TelemetryAdmission:
    """Verified, content-minimised export policy for one native turn."""

    trace_id: str
    span_id: str
    export_id: str
    native_turn_id: str
    usage_authority: str
    allow_body: bool
    body_sha256: str

    @property
    def usage(self) -> dict[str, int]:
        # The session/tool process owns no aggregate. Gateway or direct-provider
        # accounting is emitted only by its native authority, preventing double totals.
        return dict(_ZERO_USAGE)

    def project_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Return the only data an exporter may receive after admission.

        Tool and media fields are never forwarded. LIFE and unknown classes also
        omit body before this projection can cross into portable code.
        """
        result: dict[str, Any] = {
            "metadata": _metadata(payload.get("metadata") if isinstance(payload, Mapping) else None),
            "usage": self.usage,
            "trace": {
                "trace_id": self.trace_id, "span_id": self.span_id, "export_id": self.export_id,
                "native_turn_id": self.native_turn_id, "usage_authority": self.usage_authority,
            },
        }
        if self.allow_body:
            body = payload.get("body") if isinstance(payload, Mapping) else None
            if not isinstance(body, str) or _payload_sha256(body) != self.body_sha256:
                raise TelemetryAdmissionDenied("payload_body_mismatch")
            result["body"] = body
        return result


def verify_signed_admission(*, frame: Mapping[str, Any], native_context: Mapping[str, Any],
                            issuer_public_key_pem: bytes | str, body: str, now: int | None = None) -> TelemetryAdmission:
    """Verify C1's v2 frame against the core's native profile/session/turn.

    The issuer key must be supplied by the root-managed C1 adapter.  There is
    deliberately no environment fallback, plugin callback, or mutable resolver.
    """
    if not isinstance(body, str):
        raise TelemetryAdmissionDenied("body_invalid")
    identity = _identity(native_context)
    check_time = int(time.time()) if now is None else now
    if isinstance(check_time, bool) or not isinstance(check_time, int):
        raise TelemetryAdmissionDenied("clock_invalid")
    _verify_signature(frame, issuer_public_key_pem)
    authority = _verify_frame(frame, identity, body, check_time)
    trace_id, span_id, export_id = _trace_ids(identity)
    return TelemetryAdmission(
        trace_id=trace_id, span_id=span_id, export_id=export_id,
        native_turn_id=identity["native_turn_id"], usage_authority=authority,
        allow_body=_classification(native_context) == "business", body_sha256=_payload_sha256(body),
    )
