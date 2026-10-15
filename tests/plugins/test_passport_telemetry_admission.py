"""Portable Hermes must not become a Passport final-export authority."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _self_signed_business_frame():
    """A complete forged frame represents the prior caller-controlled P0."""
    key = Ed25519PrivateKey.generate()
    body = "business content must not cross this portable boundary"
    frame = {
        "schema": "aerodeck.passport-verification-receipt/v2",
        "permitted_domain": "business",
        "boundary_context": {
            "kind": "langfuse-final-export/v2", "native_turn_id": "turn-000000000001",
            "payload_sha256": "sha256:" + hashlib.sha256(
                _canonical({"body": body}).encode()
            ).hexdigest(),
        },
    }
    signature = key.sign(_canonical(frame).encode())
    frame["issuer_signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return key, frame, body


def test_portable_caller_cannot_turn_a_self_signed_frame_into_body_export():
    from hermes_cli.passport_telemetry_admission import (
        TelemetryAdmissionDenied,
        verify_signed_admission,
    )

    key, frame, body = _self_signed_business_frame()
    with pytest.raises(TelemetryAdmissionDenied, match="managed_boundary_required"):
        verify_signed_admission(
            frame=frame,
            issuer_public_key_pem=key.public_key().public_bytes_raw(),
            native_context={"classification": "business", "native_turn_id": "turn-000000000001"},
            body=body,
        )


def test_contract_requires_external_root_managed_service_and_has_no_portable_export():
    from hermes_cli.passport_telemetry_admission import managed_admission_contract

    contract = managed_admission_contract()
    assert contract == {
        "schema": "aerodeck.passport-final-export-native-admission/v1",
        "admission_service": "server-owned-c5-final-export",
        "issuer_public_key": "managed-c5-root-owned-descriptor",
        "service_owns": (
            "issuer_key", "native_profile_session_turn", "replay_ledger",
            "life_unknown_content_stripping", "gateway_direct_usage_authority",
        ),
        "portable_input": "none",
        "portable_export": "none",
        "endpoint": "not-configured-in-portable-core",
        "status": "managed_boundary_required",
    }
