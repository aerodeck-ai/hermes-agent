---
title: "Managed Telemetry Admission"
description: "A core-owned boundary for sensitive telemetry export"
---

# Managed Telemetry Admission

Hermes observer hooks are deliberately not a trust boundary for sensitive
telemetry. A plugin runs in the same interpreter as its inputs and can receive
caller-controlled hook fields. It must therefore never select an issuer key,
managed endpoint, native identity, admission result, exporter credential, or
body-export permission.

This document describes a future **disabled-by-default core integration**. It
is a source-preparation contract only: current Hermes releases have no managed
adapter, and the portable `passport_telemetry_admission` module refuses every
caller-supplied frame, key, and native context.

## Boundary ownership

The core integration creates a native-turn snapshot while binding the turn in
`agent/turn_context.py`. The snapshot is opaque to plugins and carries the
core-observed session, native turn, runtime surface, and phase. It is neither a
`ContextVar` exposed to a hook nor an object supplied by a request, plugin, or
configuration file.

A managed host component owns all trust material and egress:

- the installed adapter selection, endpoint, and issuer trust;
- native profile and workload lookup from the host's authenticated runtime;
- replay protection and expiration checks;
- classification policy and pre-export removal of body, tool payloads, and
  media for unknown, denied, or privacy-restricted traffic; and
- the final exporter credential and the single authority for gateway versus
  direct-provider usage.

The managed component receives a core-created snapshot and a canonical body
hash. It returns an authenticated, bounded decision to core. A missing,
expired, malformed, replayed, or mismatched decision leaves the event
metadata-only. The portable plugin path cannot call this component or obtain a
body-capable projection.

## Required core seams

A complete upstream implementation needs three core-owned seams, none of which
may dispatch through `PluginManager`, `invoke_hook`, the monitoring emitter, or
an environment-configured callback:

1. **Snapshot creation.** Create and retain an immutable native-turn handle at
   the existing turn-identity binding in `agent/turn_context.py`. Do not use the
   public `turn_id` alone as an authorization credential.
2. **Final projection.** After the final response has been chosen by core and
   before any exporter sees it, core asks the managed component for an admission
   decision bound to the snapshot and canonical body hash. The decision must be
   checked by core before forming the exporter payload.
3. **Usage ownership.** Core passes a per-native-turn deterministic observation
   identity to the managed exporter and records gateway or direct-provider usage
   under exactly one authority. Retries reuse that observation identity and do
   not produce an extra session or tool aggregate.

The generic core interface must not encode a person, product, endpoint, or
issuer format. A managed adapter can supply its own signed-policy protocol, but
its installation and credentials are host-managed rather than plugin-managed.

## Content rule

The projection is text-only. Before an exporter is invoked, core strips tool
arguments, tool results, function-call objects, images, audio, video, files,
and media URLs whenever the decision is absent, unknown, denied, or
privacy-restricted. Metadata-only events may carry bounded correlation and
outcome fields; they carry no prompt or response body.

## Acceptance tests for an upstream implementation

- A plugin cannot supply the issuer, endpoint, native snapshot, decision, or
  exporter credential.
- A complete self-signed frame fails before any body projection.
- Altering profile, session, native turn, body hash, expiry, or replay nonce
  fails closed.
- Unknown, denied, and privacy-restricted classifications export no body, tool
  data, or media.
- One native turn and all retries use one deterministic exporter observation.
- Gateway and direct-provider paths cannot both count usage for that turn.
- With no managed adapter installed, the core has no body-capable telemetry
  exporter.

The downstream C5 implementation can adopt this only after its independently
verified membership, managed transport, and lifecycle gates are satisfied. This
document neither installs an adapter nor enables any telemetry export.
