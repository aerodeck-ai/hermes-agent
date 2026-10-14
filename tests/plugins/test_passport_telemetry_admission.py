"""C1-signed, core-owned telemetry admission contract.

These tests exercise the public admission seam.  They deliberately do not
construct a PluginManager or a plugin context: portable code cannot publish an
admission resolver or turn a Python object into export authority.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _payload_hash(body: str) -> str:
    return "sha256:" + hashlib.sha256(_canonical({"body": body}).encode()).hexdigest()


def _signed_frame(private_key, *, body="approved business body", classification="business",
                  usage_authority="gateway", session_id="session-0000000001",
                  native_turn_id="turn-000000000001"):
    """Independent C1-v2 wire fixture; only the signature is test-local."""
    frame = {
        "schema": "aerodeck.passport-verification-receipt/v2",
        "decision_call_id": "pdc-000000000001",
        "passport_id": "passport-000000000001",
        "passport_contract_version": "aerodeck.passport/v1",
        "passport_issuer": "passport.c1",
        "passport_issuer_kid": "passport-ed25519-1",
        "passport_signature_valid": True,
        "receipt_issuer_kid": "c1-ed25519-1",
        "signature_algorithm": "Ed25519",
        "issued_at": 1_899_999_000,
        "verified_at": 1_899_999_001,
        "expires_at": 2_000_000_000,
        "verification_nonce": "nonce-000000000001",
        "request_fingerprint": "sha256:" + "0" * 64,
        "policy_decision": "ALLOW",
        "policy_action": "langfuse.final-export.emit",
        "audiences": ["langfuse.final-export"],
        "capabilities": ["langfuse.final-export.emit"],
        "permitted_domain": "business",
        "permitted_tenant": "business",
        "permitted_actor": {
            "profile_id": "profile-henry", "session_id": session_id,
            "native_turn_id": native_turn_id, "host_id": "henrys-macbook-pro",
            "workload_id": "hermes", "human_owner": "henry",
        },
        "passport_claims": {
            "profile_id": "profile-henry", "session_id": session_id,
            "native_turn_id": native_turn_id, "host_id": "henrys-macbook-pro",
            "workload_id": "hermes", "human_owner": "henry", "estate": "business",
        },
        "verified_runtime_membership": {
            "provider": "aer", "runtime": "hermes", "surface": "aer-hermes",
            "profile_id": "profile-henry",
        },
        "verified_product": "none",
        "usage_authority": usage_authority,
        "boundary_context": {
            "kind": "langfuse-final-export/v2", "native_turn_id": native_turn_id,
            "surface": "aer-hermes", "payload_sha256": _payload_hash(body),
        },
    }
    frame["issuer_signature"] = _b64(private_key.sign(_canonical(frame).encode()))
    return frame, body, classification


def _resign(frame, private_key):
    unsigned = dict(frame)
    unsigned.pop("issuer_signature", None)
    unsigned["issuer_signature"] = _b64(private_key.sign(_canonical(unsigned).encode()))
    return unsigned


def _native_context(classification="business", *, session_id="session-0000000001",
                    native_turn_id="turn-000000000001"):
    return {
        "profile_id": "profile-henry", "session_id": session_id,
        "native_turn_id": native_turn_id, "host_id": "henrys-macbook-pro",
        "workload_id": "hermes", "human_owner": "henry",
        "classification": classification,
    }


def _public_pem(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_native_admission_verifies_c1_signature_and_binds_profile_session_turn():
    from hermes_cli.passport_telemetry_admission import verify_signed_admission

    key = Ed25519PrivateKey.generate()
    frame, body, _ = _signed_frame(key)
    policy = verify_signed_admission(
        frame=frame, native_context=_native_context(), issuer_public_key_pem=_public_pem(key),
        body=body, now=1_900_000_000,
    )

    # C1's published v1 seed: profile/session root + native-turn generation.
    session_seed = "v1|hermes|macbook|hermes|profile-henry|henry|session-0000000001"
    trace_id = hashlib.sha256(session_seed.encode()).hexdigest()[:32]
    assert policy.trace_id == trace_id
    assert policy.span_id == hashlib.sha256((session_seed + "|ExecutionStart").encode()).hexdigest()[:16]
    assert policy.export_id == "pfe_" + hashlib.sha256(
        (trace_id + "|turn-000000000001").encode()
    ).hexdigest()[:32]
    assert policy.allow_body is True
    assert policy.usage == {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cached_tokens": 0}


def test_native_admission_rejects_forged_or_mismatched_signed_frame():
    from hermes_cli.passport_telemetry_admission import TelemetryAdmissionDenied, verify_signed_admission

    key = Ed25519PrivateKey.generate()
    frame, body, _ = _signed_frame(key)
    frame["permitted_actor"] = dict(frame["permitted_actor"], native_turn_id="turn-000000000099")
    with pytest.raises(TelemetryAdmissionDenied, match="signature"):
        verify_signed_admission(
            frame=frame, native_context=_native_context(), issuer_public_key_pem=_public_pem(key),
            body=body, now=1_900_000_000,
        )

    mismatched, body, _ = _signed_frame(key, native_turn_id="turn-000000000099")
    with pytest.raises(TelemetryAdmissionDenied, match="native_binding"):
        verify_signed_admission(
            frame=mismatched, native_context=_native_context(), issuer_public_key_pem=_public_pem(key),
            body=body, now=1_900_000_000,
        )


def test_native_admission_rejects_re_signed_incomplete_c1_frame():
    from hermes_cli.passport_telemetry_admission import TelemetryAdmissionDenied, verify_signed_admission

    key = Ed25519PrivateKey.generate()
    frame, body, _ = _signed_frame(key)
    frame.pop("request_fingerprint")
    with pytest.raises(TelemetryAdmissionDenied, match="request_fingerprint"):
        verify_signed_admission(
            frame=_resign(frame, key), native_context=_native_context(), issuer_public_key_pem=_public_pem(key),
            body=body, now=1_900_000_000,
        )

@pytest.mark.parametrize("classification", ["life", "unknown"])
def test_life_and_unknown_never_export_body_tool_or_media(classification):
    from hermes_cli.passport_telemetry_admission import verify_signed_admission

    key = Ed25519PrivateKey.generate()
    frame, body, _ = _signed_frame(key, classification=classification)
    policy = verify_signed_admission(
        frame=frame, native_context=_native_context(classification), issuer_public_key_pem=_public_pem(key),
        body=body, now=1_900_000_000,
    )

    assert policy.allow_body is False
    assert policy.project_payload({"body": body, "tool_calls": [{"arguments": "private"}], "media": "data:image/png;base64,AA=="}) == {
        "metadata": {},
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cached_tokens": 0},
        "trace": {"trace_id": policy.trace_id, "span_id": policy.span_id, "export_id": policy.export_id,
                  "native_turn_id": "turn-000000000001", "usage_authority": "gateway"},
    }


def test_direct_authority_does_not_give_session_tools_usage_totals_or_tool_media():
    from hermes_cli.passport_telemetry_admission import verify_signed_admission

    key = Ed25519PrivateKey.generate()
    frame, body, _ = _signed_frame(key, usage_authority="direct-provider")
    policy = verify_signed_admission(
        frame=frame, native_context=_native_context(), issuer_public_key_pem=_public_pem(key),
        body=body, now=1_900_000_000,
    )

    projected = policy.project_payload({
        "body": body, "tool_calls": [{"arguments": "never export"}],
        "media": "data:image/png;base64,AA==", "metadata": {"model": "safe-model"},
    })
    assert projected == {
        "body": body, "metadata": {"model": "safe-model"},
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cached_tokens": 0},
        "trace": {"trace_id": policy.trace_id, "span_id": policy.span_id, "export_id": policy.export_id,
                  "native_turn_id": "turn-000000000001", "usage_authority": "direct-provider"},
    }
