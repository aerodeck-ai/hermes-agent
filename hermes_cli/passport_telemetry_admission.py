"""Fail-closed boundary for managed Passport telemetry admission.

Portable Hermes code cannot be an admission authority. In particular it must
not accept a caller-selected issuer key, native profile/session/turn context,
or a frame that a plugin can manufacture. Python object privacy and frozen
dataclasses do not create a boundary against a plugin in the same interpreter.

The only body-capable implementation is therefore an external, root-managed
native-admission service. It owns the pinned issuer public key, derives the
active native turn itself, keeps the replay ledger, and passes an already
minimised projection directly to the core exporter. That service and its
core-only hand-off are deliberately not implemented by this portable package.

Until that managed integration exists, this module is explicitly
non-export-capable. It exports no constructor or verifier which can turn a
frame into an export permission.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


MANAGED_ADMISSION_CONTRACT = {
    "schema": "aerodeck.passport-final-export-native-admission/v1",
    "admission_service": "/run/aerodeck/passport-final-export-admission.sock",
    "issuer_public_key": "/etc/aerodeck/c5/passport-final-export-issuer.pub",
    "service_owns": (
        "issuer_key", "native_profile_session_turn", "replay_ledger",
        "life_unknown_content_stripping", "gateway_direct_usage_authority",
    ),
    "portable_input": "none",
    "portable_export": "none",
    "status": "managed_boundary_required",
}


class TelemetryAdmissionDenied(ValueError):
    """No portable caller is an authority to export a telemetry body."""


def managed_admission_contract() -> dict[str, Any]:
    """Return the fixed source contract without opening a service connection."""
    return dict(MANAGED_ADMISSION_CONTRACT)


def verify_signed_admission(**_caller_values: Mapping[str, Any]) -> None:
    """Refuse legacy caller-supplied frame/key/context admission.

    Kept only as a compatibility tripwire for a pre-release fork branch. It
    cannot verify or project any payload. The managed native service must hand
    its projection directly to the core exporter in a later integration.
    """
    raise TelemetryAdmissionDenied("managed_boundary_required")
