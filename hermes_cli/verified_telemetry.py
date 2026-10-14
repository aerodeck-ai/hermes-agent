"""Verifier-owned, content-free telemetry receipts for portable plugins.

Passport/JWS validation stays at the host admission boundary.  This module carries
only the verified projection that plugins may use for telemetry policy; it never
carries a bearer, raw Passport, prompt body, or secret.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Optional

UsageAuthority = Literal["gateway", "direct-provider"]


@dataclass(frozen=True)
class VerifiedTelemetryReceipt:
    """A session-bound projection emitted by the core verifier after validation."""
    runtime: str
    host: str
    seat: str
    profile: str
    person: str
    session: str
    phase: str
    trace_class: str
    provider: str
    product: str
    surface: str
    usage_authority: UsageAuthority

    def plugin_projection(self, *, session_id: str) -> Optional[dict[str, object]]:
        """Return bounded fields only when this receipt is for the active session."""
        if not session_id or self.session != session_id:
            return None
        values = (self.runtime, self.host, self.seat, self.profile, self.person,
                  self.session, self.phase, self.trace_class, self.provider,
                  self.product, self.surface)
        if any(not isinstance(value, str) or not value or len(value) > 200 for value in values):
            return None
        if self.usage_authority not in ("gateway", "direct-provider"):
            return None
        return {
            "attribution": {
                "runtime": self.runtime, "host": self.host, "seat": self.seat,
                "profile": self.profile, "person": self.person, "session": self.session,
                "phase": self.phase, "trace_class": self.trace_class,
            },
            "membership": {"provider": self.provider, "product": self.product,
                           "surface": self.surface, "profile": self.profile},
            "usage_authority": self.usage_authority,
        }


VerifiedTelemetryReceiptResolver = Callable[[str], Optional[VerifiedTelemetryReceipt]]
