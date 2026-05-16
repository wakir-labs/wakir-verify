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
quorum verdict. Cross-library witness is the contract: if a third
party can reproduce the verdict without any Wakir code, the audit
trail's Bitcoin-anchor claim is independently checkable.

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

* **Quorum default is 3/4.** A single pole disagreeing with three
  others (because of, e.g., an Esplora 503 or a mempool.space
  rate-limit) must not flip the overall verdict. A 3/4 quorum
  threshold tolerates one transient pole failure without
  weakening the cross-library witness contract; an operator can
  request 4/4 with ``--pols all`` for stricter mode.

* **Sandbox-safe by default.** The HTTP-shaped poles
  (``pole_mempool_space``, ``pole_esplora_blockstream``) accept a
  per-call ``transport`` argument so tests can inject a fake
  HTTP client. The ``ots`` CLI pole accepts a per-call
  ``ots_runner`` callable for the same reason. No live network
  call happens in the test suite.

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
