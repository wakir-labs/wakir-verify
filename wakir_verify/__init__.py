# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors
#
# This sub-package ships under Apache-2.0 (not BUSL-1.1 like the
# rest of wat/). The external-verifier surface is part of the
# brand-proof contract that third-party auditors are meant to run
# against Wakir-produced audit trails without operating any
# Wakir-controlled software; locking it under BSL would defeat the
# point.

"""External-verifier cross-library witness layer for WAT anchors.

This sub-package materialises the Position-Paper §L4-References
4-pole-cross-library-verifier annex. It exposes a single public
entry point, :func:`verify_wat_anchor`, that runs an OpenTimestamps
proof and the Merkle-root it attests to through four independent
implementations (`pole_python_stdlib`, `pole_ots_cli`,
`pole_mempool_space`, `pole_esplora_blockstream`) and emits a
verdict. Cross-library witness is the contract: if a third party can
reproduce the verdict without any Wakir code, the audit trail's
Bitcoin-anchor claim is independently checkable.

Four claims, not one word
-------------------------

A verification result is four separate statements — hash-list
consistency, event binding, payload check, root authenticity — with an
``ok`` / ``failed`` / ``not_checked`` status each. See
:mod:`wakir_verify.claims`. ``not_checked`` is never shorthand for
``ok``: a verifier that cannot make a claim says so.

Design posture
--------------

* **Boring-tech first.** Three of the four poles use only the
  Python standard library (``hashlib``, ``urllib.request``,
  ``subprocess``). The fourth shells out to the ``ots`` CLI
  binary, which is the upstream OpenTimestamps reference
  implementation. No third-party Python dependency is required.

* **Pole independence.** Each pole module exposes a single
  function ``verify(...) -> PoleResult`` and depends on nothing
  inside the sub-package other than the shared dataclass module.
  Replacing or removing one pole touches exactly one file.

* **The mandatory check outranks the quorum.** Poles carry a role.
  ``pole_python_stdlib`` and ``pole_ots_cli`` are *mandatory*: they
  can tie an anchor to a Bitcoin attestation. The two Esplora poles
  are *supporting*: they observe the chain. A positive verdict needs
  a mandatory pole to have bound the root, the quorum threshold to be
  met, and no pole to have reported a contradiction. Before
  2026-09-14 the threshold was the entire decision, and three poles
  that never looked at the root could — and did — outvote the one
  that reported failure.

* **Quorum default is 3/4** for the supporting evidence. A single
  pole failing on an Esplora 503 or a rate-limit does not flip a
  verdict that a mandatory pole established; ``--pols all`` is the
  stricter mode. What the threshold can no longer do is manufacture a
  verdict on its own.

* **Sandbox-safe by default.** The HTTP-shaped poles
  (``pole_mempool_space``, ``pole_esplora_blockstream``) accept a
  per-call ``transport`` argument so tests can inject a fake
  HTTP client. The ``ots`` CLI pole accepts a per-call
  ``ots_runner`` callable for the same reason. No live network
  call happens in the test suite.

  Note that ``pole_ots_cli`` in its default ``verify`` mode is not
  offline *in production*: upstream ``ots verify`` upgrades pending
  attestations against the calendars and reads a block header from a
  Bitcoin node. ``pole_python_stdlib`` is the offline path, and it is
  the one that reports ``not_checked`` rather than reaching for the
  network on its own.

Public API
----------

The only stable surface is :func:`verify_wat_anchor` and the
:class:`AnchorVerification` dataclass it returns. Pole modules are
re-exported as ``poles`` for advanced callers who want to drive a
single pole in isolation.
"""

from __future__ import annotations

from wakir_verify import poles
from wakir_verify.aggregator import (
    AnchorVerification,
    PoleResult,
    QuorumPolicy,
    summarise_discrepancies,
    verify_wat_anchor,
)

__all__ = [
    "AnchorVerification",
    "PoleResult",
    "QuorumPolicy",
    "poles",
    "summarise_discrepancies",
    "verify_wat_anchor",
]
