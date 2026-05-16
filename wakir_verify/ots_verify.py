# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""High-level OTS-verify wrapper around the 4-pole external verifier.

This module is the *programmatic* entry point for callers that want
to verify a WAT anchor against a Bitcoin attestation without
shelling out to the CLI. The CLI in :mod:`wakir_verify.cli` is the
operator surface; this module is the library surface.

Both surfaces drive the same underlying 4-pole verifier in
:mod:`wakir_verify.aggregator`.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from wakir_verify.aggregator import (
    AnchorVerification,
    QuorumPolicy,
    verify_wat_anchor,
)


def verify_anchor(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    quorum_policy: QuorumPolicy = QuorumPolicy.THREE_OF_FOUR,
    enabled_poles: Optional[list[str]] = None,
    pole_overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> AnchorVerification:
    """Verify *anchor_hash* against the OTS receipt at *ots_proof_path*.

    Thin keyword-only wrapper around
    :func:`wakir_verify.aggregator.verify_wat_anchor` so library
    callers get an explicit signature.

    Returns an :class:`AnchorVerification` with per-pole evidence and
    the quorum outcome. Does not exit the interpreter; the caller
    decides whether a non-quorum result is fatal.
    """
    return verify_wat_anchor(
        anchor_hash=anchor_hash,
        ots_proof_path=ots_proof_path,
        quorum_policy=quorum_policy,
        enabled_poles=enabled_poles,
        pole_overrides=pole_overrides,
    )


__all__ = [
    "verify_anchor",
    "QuorumPolicy",
    "AnchorVerification",
]
