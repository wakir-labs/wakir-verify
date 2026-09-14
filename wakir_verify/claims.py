# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""The four claims a Wakir Audit Trail verification can make.

A single word — ``verified`` — was doing the work of four very
different statements, and the weakest of them was setting the tone.
This module separates them so neither the CLI text nor the JSON can
imply more than was actually checked:

``hashlist_consistency``
    The manifest's stored leaf hashes fold, in manifest order and
    under the Bitcoin-pattern padding rule, to the manifest's stored
    Merkle root. This is arithmetic over numbers the manifest states
    about itself. It says nothing about the events.

``event_binding``
    The leaf hashes were re-derived from the four B1 event fields
    (``event_id``, ``time``, ``payload_hash``, ``capability_token_hash``)
    rather than taken on trust. Strength depends on where the fields
    came from — see :mod:`wakir_verify.binding`, which records the
    source in the claim's evidence.

``payload_check``
    Payload bytes supplied by the caller hash to the ``payload_hash``
    the leaf commits to. Without payload bytes there is nothing to
    check and the claim stays ``not_checked``; the audit trail commits
    to a digest, and a digest is not its preimage.

``root_authenticity``
    A complete, root-bound timestamp verification puts the Merkle root
    in the Bitcoin chain at a stated height. This is the only claim
    that involves Bitcoin at all.

Status vocabulary
-----------------

``ok``
    Checked, and it held.
``failed``
    Checked, and it did not hold.
``not_checked``
    Not checked. Never a synonym for ``ok``. A verifier that cannot
    make a claim says so; an honestly disabled time proof is
    acceptable, a false positive is not.

The overall verdict is deliberately unforgiving: any ``failed`` makes
it ``failed``, and only an all-``ok`` set makes it ``verified``.
Everything else is ``not_checked``. There is no averaging and no
voting between claims — they are different statements, not opinions
about the same statement.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, Iterable, List, Mapping, Tuple

#: Checked and true.
STATUS_OK = "ok"
#: Checked and false.
STATUS_FAILED = "failed"
#: Not checked; makes no assertion in either direction.
STATUS_NOT_CHECKED = "not_checked"

VALID_STATUSES = (STATUS_OK, STATUS_FAILED, STATUS_NOT_CHECKED)

CLAIM_HASHLIST = "hashlist_consistency"
CLAIM_EVENT_BINDING = "event_binding"
CLAIM_PAYLOAD = "payload_check"
CLAIM_ROOT_AUTHENTICITY = "root_authenticity"

#: Canonical order for rendering. Narrowest statement first, the one
#: an external reader is most likely to over-read last.
CLAIM_ORDER: Tuple[str, ...] = (
    CLAIM_HASHLIST,
    CLAIM_EVENT_BINDING,
    CLAIM_PAYLOAD,
    CLAIM_ROOT_AUTHENTICITY,
)

#: One-line statement of what each claim asserts when it is ``ok``.
CLAIM_QUESTIONS: Dict[str, str] = {
    CLAIM_HASHLIST: (
        "Do the manifest's stored leaf hashes fold to its stored root?"
    ),
    CLAIM_EVENT_BINDING: (
        "Do the recorded event fields re-derive those leaf hashes?"
    ),
    CLAIM_PAYLOAD: (
        "Do the supplied payload bytes hash to the committed payload_hash?"
    ),
    CLAIM_ROOT_AUTHENTICITY: (
        "Is the root bound into the Bitcoin chain by a complete timestamp "
        "proof?"
    ),
}


@dataclasses.dataclass(frozen=True)
class Claim:
    """One verification claim with its status and supporting evidence."""

    name: str
    status: str
    summary: str
    evidence: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"claim {self.name!r} has invalid status {self.status!r}; "
                f"expected one of {VALID_STATUSES}"
            )

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim": self.name,
            "question": CLAIM_QUESTIONS.get(self.name, ""),
            "status": self.status,
            "summary": self.summary,
            "evidence": dict(self.evidence),
        }


def not_checked(name: str, summary: str, **evidence: Any) -> Claim:
    """Build a ``not_checked`` claim. Kept short because it is common."""
    return Claim(
        name=name, status=STATUS_NOT_CHECKED, summary=summary, evidence=evidence
    )


@dataclasses.dataclass(frozen=True)
class ClaimSet:
    """The four claims plus the overall verdict they compose into."""

    claims: Tuple[Claim, ...]

    @classmethod
    def from_iterable(cls, claims: Iterable[Claim]) -> "ClaimSet":
        by_name = {c.name: c for c in claims}
        ordered: List[Claim] = []
        for name in CLAIM_ORDER:
            ordered.append(
                by_name.pop(name, None)
                or not_checked(name, "not evaluated by this run")
            )
        ordered.extend(by_name.values())  # forward-compat: unknown claims last
        return cls(claims=tuple(ordered))

    def get(self, name: str) -> Claim:
        for claim in self.claims:
            if claim.name == name:
                return claim
        raise KeyError(name)

    @property
    def overall_status(self) -> str:
        """``failed`` beats ``not_checked`` beats ``ok``.

        A single failed claim sinks the verdict even if everything
        else is green; a single unchecked claim withholds it. Only an
        all-``ok`` set earns ``verified``.
        """
        if any(c.status == STATUS_FAILED for c in self.claims):
            return STATUS_FAILED
        if all(c.status == STATUS_OK for c in self.claims):
            return "verified"
        return STATUS_NOT_CHECKED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "claims": [c.to_dict() for c in self.claims],
        }


__all__ = [
    "CLAIM_EVENT_BINDING",
    "CLAIM_HASHLIST",
    "CLAIM_ORDER",
    "CLAIM_PAYLOAD",
    "CLAIM_QUESTIONS",
    "CLAIM_ROOT_AUTHENTICITY",
    "Claim",
    "ClaimSet",
    "STATUS_FAILED",
    "STATUS_NOT_CHECKED",
    "STATUS_OK",
    "VALID_STATUSES",
    "not_checked",
]
