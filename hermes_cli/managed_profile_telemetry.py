"""Bridge verified managed-profile admission into portable-plugin telemetry.

The managed-profile bootstrap owns publication.  This module deliberately accepts
only a verifier callable supplied by that bootstrap: it reads neither auth files
nor tokens and creates no Passport-shaped data itself.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Optional

from hermes_cli.verified_telemetry import VerifiedTelemetryReceipt

NativeProfileReceiptVerifier = Callable[[str, Path], Optional[VerifiedTelemetryReceipt]]

_lock = threading.RLock()
_published: tuple[object, NativeProfileReceiptVerifier] | None = None


def publish_managed_profile_telemetry_verifier(owner: object, verifier: NativeProfileReceiptVerifier) -> None:
    """Publish the canonical native-profile verifier after its bootstrap validated identity.

    ``owner`` lets shutdown clear only its own publication.  This API is for the
    core bootstrap, never a portable plugin registrar.
    """
    if not callable(verifier):
        raise TypeError("managed profile telemetry verifier must be callable")
    global _published
    with _lock:
        _published = (owner, verifier)
    _refresh_existing_plugin_managers()


def clear_managed_profile_telemetry_verifier(owner: object) -> None:
    """Clear a bootstrap verifier only when its owning lifecycle ends."""
    global _published
    changed = False
    with _lock:
        if _published is not None and _published[0] is owner:
            _published = None
            changed = True
    if changed:
        _refresh_existing_plugin_managers()


def _refresh_existing_plugin_managers() -> None:
    """Update already-created profile managers when native bootstrap changes."""
    try:
        from hermes_cli.plugins import _known_plugin_managers
        for manager in _known_plugin_managers():
            manager._verified_telemetry_receipt_resolver = resolver_for_managed_profile(manager.home_path)
    except Exception:
        # Bootstrap telemetry can never impair plugin manager creation or teardown.
        return


def resolver_for_managed_profile(home: str | Path) -> Optional[Callable[[str], Optional[VerifiedTelemetryReceipt]]]:
    """Return a profile-bound resolver, or ``None`` before native bootstrap publishes one."""
    with _lock:
        item = _published
    if item is None:
        return None
    _owner, verifier = item
    profile_home = Path(home)

    def resolve(session_id: str) -> Optional[VerifiedTelemetryReceipt]:
        try:
            receipt = verifier(session_id, profile_home)
        except Exception:
            return None
        return receipt if isinstance(receipt, VerifiedTelemetryReceipt) else None

    return resolve
