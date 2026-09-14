# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Shared dataclasses for the external-verifier sub-package.

This module exists to break the import cycle between the pole
implementations (``poles.py``) and the aggregator (``aggregator.py``):
both need :class:`PoleResult`, and the aggregator additionally
imports the pole functions. Hoisting the dataclass into a leaf
module keeps the dependency graph one-way.

Verdict vocabulary
------------------

Every pole used to report ``verified`` or ``failed``, which flattened
"I walked the proof and it binds this root to a Bitcoin block" and "an
HTTP endpoint answered my question about a block height" into the same
word — and then let the second outvote the first. The vocabulary is
now explicit about what a pole actually did:

``verified``
    Root-bound and complete. The pole tied *this* anchor to a Bitcoin
    attestation. Only a mandatory pole can say this.
``structural_ok``
    The input parses and is internally coherent, but the pole did not
    tie the anchor to Bitcoin.
``block_observed``
    An independent operator was asked about a block and answered.
    Evidence about the chain, not about the anchor.
``not_checked``
    The pole could have checked but was not given what it needed
    (no block header source, no proof reader). Not a failure, and
    emphatically not a pass.
``failed``
    Checked and contradicted.
``unavailable``
    The pole could not run at all (binary missing, transport error).

Pole roles
----------

``mandatory``
    Can produce a root-bound verdict. A positive overall verdict
    requires one of these to say ``verified``.
``supporting``
    Contributes evidence. No number of supporting poles substitutes
    for a mandatory one.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Mapping

#: Root-bound and complete: this anchor is tied to a Bitcoin attestation.
VERDICT_VERIFIED = "verified"
#: Parses and is internally coherent; no tie to Bitcoin.
VERDICT_STRUCTURAL_OK = "structural_ok"
#: An independent operator answered a question about a block.
VERDICT_BLOCK_OBSERVED = "block_observed"
#: Checkable in principle, but the pole was not given what it needed.
VERDICT_NOT_CHECKED = "not_checked"
#: Checked and contradicted.
VERDICT_FAILED = "failed"
#: Could not run at all.
VERDICT_UNAVAILABLE = "unavailable"

#: Verdicts that assert something positive about the anchor itself.
ROOT_BOUND_VERDICTS = (VERDICT_VERIFIED,)

#: A pole that can produce a root-bound verdict.
ROLE_MANDATORY = "mandatory"
#: A pole that contributes evidence but cannot bind the root.
ROLE_SUPPORTING = "supporting"


@dataclasses.dataclass(frozen=True)
class PoleResult:
    """Outcome of running a single verification pole.

    See ``aggregator.PoleResult`` re-export for the documented
    public surface; this is the same dataclass.
    """

    name: str
    ok: bool
    verdict: str
    witness: Mapping[str, Any]
    note: str = ""
    role: str = ROLE_SUPPORTING

    @property
    def is_root_bound(self) -> bool:
        """True when this result asserts a root-bound Bitcoin verification."""
        return self.role == ROLE_MANDATORY and self.verdict in ROOT_BOUND_VERDICTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "verdict": self.verdict,
            "role": self.role,
            "witness": dict(self.witness),
            "note": self.note,
        }


__all__ = [
    "PoleResult",
    "ROLE_MANDATORY",
    "ROLE_SUPPORTING",
    "ROOT_BOUND_VERDICTS",
    "VERDICT_BLOCK_OBSERVED",
    "VERDICT_FAILED",
    "VERDICT_NOT_CHECKED",
    "VERDICT_STRUCTURAL_OK",
    "VERDICT_UNAVAILABLE",
    "VERDICT_VERIFIED",
]
