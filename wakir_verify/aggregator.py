# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""4-pole cross-library aggregator for WAT anchor verification.

The aggregator runs each configured pole against the same input
(merkle root hash plus OTS proof file) and folds the per-pole
verdicts into a quorum decision. The cross-library witness contract
is documented in the Position-Paper §L4-References annex; this
module is the executable form.

Aggregator semantics
--------------------

Each pole returns a :class:`PoleResult` with:

* ``ok`` — a boolean: did this pole independently verify the anchor?
* ``verdict`` — one of ``"verified"``, ``"failed"``, ``"unavailable"``
  (when the pole could not run at all, e.g. CLI binary missing or
  HTTP transport returned an error).
* ``witness`` — a free-form dict that captures the substance the
  pole observed (block hash, height, ``ots`` output snippet, …)
  so a human auditor can correlate verdicts across poles.

The mandatory check outranks the quorum
---------------------------------------

Counting ``ok`` votes was the whole decision procedure, and it had no
notion that the poles answer different questions. A file that was not
a timestamp proof — magic header plus the literal text
``BitcoinBlockHeaderAttestation(800000)`` — collected three ``ok``
votes from poles that never looked at the root, outvoted the one pole
that reported failure, and reached quorum. Handing the same call a
completely different ``anchor_hash`` changed nothing.

So the decision now has two stages:

1. **Mandatory.** At least one pole with ``role == "mandatory"`` must
   return a root-bound verdict (``verified``). These are the poles
   that tie *this* anchor to a Bitcoin attestation.
2. **Supporting.** The configured quorum threshold must additionally
   be met, and no pole may have returned ``failed``.

``overall_status`` is therefore one of ``verified``, ``failed`` or
``not_checked``, and ``quorum`` is true only for ``verified``. An
observation-only run — no ``ots`` binary, no block header — lands on
``not_checked``. That is the honest answer, and it is the one an
operator can act on; a false ``verified`` is not.

Quorum
------

The quorum threshold still governs the supporting evidence:

* ``QuorumPolicy.THREE_OF_FOUR`` (default) — at least three poles
  return ``ok=True``. This tolerates one transient unavailable pole.
* ``QuorumPolicy.ALL`` — every pole must return ``ok=True``.
* ``QuorumPolicy.TWO_OF_FOUR`` — for archive-debugging scenarios
  where two poles are known unavailable; **never** the default in
  production.

A pole that returns ``unavailable`` counts as a non-vote, not a
``False`` vote — except under ``QuorumPolicy.ALL`` where any
non-``True`` fails the quorum. Rationale: a network blip on
mempool.space should not flip a finalised verified anchor to
failed; a stricter operator can opt into ``ALL``.
"""

from __future__ import annotations

import dataclasses
import enum
from typing import Any, Callable, Mapping, Optional

from wakir_verify import poles as _poles
from wakir_verify.types import (
    ROLE_MANDATORY,
    PoleResult,
    VERDICT_FAILED,
)


# ---------------------------------------------------------------------------
# Public dataclasses and enums
# ---------------------------------------------------------------------------


class QuorumPolicy(str, enum.Enum):
    """Quorum threshold for the aggregator's ``ok`` verdict."""

    #: At least three poles must return ``ok=True``. Default.
    THREE_OF_FOUR = "3-of-4"
    #: All four poles must return ``ok=True``.
    ALL = "all"
    #: At least two poles must return ``ok=True``. Debug-only.
    TWO_OF_FOUR = "2-of-4"


@dataclasses.dataclass(frozen=True)
class AnchorVerification:
    """Aggregated outcome of an :func:`verify_wat_anchor` call.

    Attributes
    ----------
    anchor_hash:
        The 32-byte merkle root hash that was checked, lowercase hex.
    quorum_policy:
        The :class:`QuorumPolicy` requested at call time.
    quorum:
        ``True`` only when ``overall_status`` is ``"verified"``: a
        mandatory pole bound the root *and* the supporting threshold
        was met *and* nothing failed. Reading this field as "three
        endpoints agreed" is exactly the misreading that let a
        non-proof pass.
    overall_status:
        ``"verified"``, ``"failed"`` or ``"not_checked"``.
    mandatory_verified_by:
        Names of the mandatory poles that produced a root-bound
        verdict. Empty means no pole tied the anchor to Bitcoin.
    supporting_quorum:
        ``True`` when the raw ``ok``-count met the policy threshold.
        Evidence, not a verdict.
    pole_results:
        Per-pole :class:`PoleResult` keyed by pole name.
    witnesses:
        Compact list of ``(pole_name, witness_dict)`` for callers
        that want to render an audit table without flattening
        ``pole_results`` themselves.
    """

    anchor_hash: str
    quorum_policy: QuorumPolicy
    quorum: bool
    pole_results: dict[str, PoleResult]
    witnesses: list[tuple[str, Mapping[str, Any]]]
    overall_status: str = "not_checked"
    mandatory_verified_by: tuple[str, ...] = ()
    supporting_quorum: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_hash": self.anchor_hash,
            "quorum_policy": self.quorum_policy.value,
            "overall_status": self.overall_status,
            "quorum": self.quorum,
            "mandatory_check": {
                "required": True,
                "satisfied": bool(self.mandatory_verified_by),
                "verified_by": list(self.mandatory_verified_by),
                "contract": (
                    "a positive verdict requires a root-bound timestamp "
                    "verification; block observations cannot substitute"
                ),
            },
            "supporting_quorum": self.supporting_quorum,
            "pole_results": {
                name: pr.to_dict() for name, pr in self.pole_results.items()
            },
        }


# ---------------------------------------------------------------------------
# Pole registry
# ---------------------------------------------------------------------------


#: Mapping from pole name to ``(verify-callable, doc-string)``. The order
#: is the canonical pole order rendered in CLI output and ``to_dict``.
POLE_REGISTRY: dict[str, Callable[..., PoleResult]] = {
    "pole_python_stdlib": _poles.pole_python_stdlib_verify,
    "pole_ots_cli": _poles.pole_ots_cli_verify,
    "pole_mempool_space": _poles.pole_mempool_space_verify,
    "pole_esplora_blockstream": _poles.pole_esplora_blockstream_verify,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_wat_anchor(
    anchor_hash: str,
    ots_proof_path: str,
    *,
    quorum_policy: QuorumPolicy = QuorumPolicy.THREE_OF_FOUR,
    enabled_poles: Optional[list[str]] = None,
    pole_overrides: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> AnchorVerification:
    """Run the 4-pole cross-library verifier on a WAT anchor.

    Parameters
    ----------
    anchor_hash:
        Lowercase 64-hex-char string. The merkle root the OTS proof
        attests to.
    ots_proof_path:
        Filesystem path to the ``.ots`` receipt file.
    quorum_policy:
        Threshold policy. See :class:`QuorumPolicy`.
    enabled_poles:
        Optional list of pole names to run. ``None`` runs every
        pole in :data:`POLE_REGISTRY`. Useful for narrow re-runs.
    pole_overrides:
        Mapping ``pole_name -> kwargs`` for per-pole injection
        (transport mocks, alternative base URLs, custom CLI runner).
        Tests use this to keep the suite fully offline.

    Returns
    -------
    :class:`AnchorVerification`
    """
    if not _is_hex_hash(anchor_hash):
        raise ValueError(
            f"anchor_hash must be a 64-char lowercase hex string, got "
            f"{anchor_hash!r}"
        )

    names = enabled_poles or list(POLE_REGISTRY.keys())
    overrides = pole_overrides or {}

    pole_results: dict[str, PoleResult] = {}
    for name in names:
        if name not in POLE_REGISTRY:
            raise ValueError(f"unknown pole: {name}")
        kwargs = dict(overrides.get(name, {}))
        try:
            result = POLE_REGISTRY[name](
                anchor_hash=anchor_hash,
                ots_proof_path=ots_proof_path,
                **kwargs,
            )
        except Exception as exc:  # noqa: BLE001 - poles must never crash aggregator
            result = PoleResult(
                name=name,
                ok=False,
                verdict="unavailable",
                witness={},
                note=f"pole crashed: {type(exc).__name__}: {exc}",
            )
        pole_results[name] = result

    supporting_quorum = _evaluate_quorum(pole_results, quorum_policy)
    mandatory_verified_by = tuple(
        name for name, pr in pole_results.items() if pr.is_root_bound
    )
    overall_status = _evaluate_overall(
        pole_results,
        supporting_quorum=supporting_quorum,
        mandatory_verified_by=mandatory_verified_by,
    )
    witnesses = [(name, pr.witness) for name, pr in pole_results.items()]

    return AnchorVerification(
        anchor_hash=anchor_hash,
        quorum_policy=quorum_policy,
        quorum=overall_status == "verified",
        pole_results=pole_results,
        witnesses=witnesses,
        overall_status=overall_status,
        mandatory_verified_by=mandatory_verified_by,
        supporting_quorum=supporting_quorum,
    )


# ---------------------------------------------------------------------------
# Discrepancy summary (determinism-audit helper)
# ---------------------------------------------------------------------------


def summarise_discrepancies(
    verification: AnchorVerification,
) -> dict[str, Any]:
    """Audit-grade summary of inter-pole disagreement.

    The 4-pole cross-library witness contract claims that four
    independent implementations agree on the same anchor. When they
    do not, the auditor needs a structured report (not a free-form
    note) that names the disagreeing poles, the dimension of
    disagreement, and a severity classification:

    * ``"none"`` — every pole that voted ``ok`` agreed on the
      observed block hash and height; pole-level ``unavailable``
      verdicts do not count as discrepancy (a silent pole is not a
      disagreeing pole).
    * ``"silent-minority"`` — one or more poles returned
      ``unavailable`` but no two ``ok`` poles disagree on substance.
      Quorum may still pass under 3-of-4. Audit-note severity.
    * ``"substance"`` — two or more ``ok`` poles disagree on the
      observed block hash at the same height, or one pole reports
      ``failed`` while others report positively. Auditor must
      examine.
    * ``"brand-critical"`` — two or more poles flip to ``failed``
      while the rest still report positively. The 4-pole
      cross-library claim is materially weakened; this is the marker
      the brand-proof contract calls out.

    This summary is diagnostic detail, not the verdict. Any
    ``failed`` pole already sinks ``overall_status``; the severity
    grading exists so an auditor can tell a one-endpoint hiccup from
    a systematic divergence, not so a caller can decide how much
    disagreement to tolerate.

    Returns a dict (not a dataclass — additive, no schema-break to
    :class:`AnchorVerification`). Callers can attach this to an
    audit-report alongside ``verification.to_dict()``.
    """
    pole_results = verification.pole_results
    ok_poles = [(n, pr) for n, pr in pole_results.items() if pr.ok]
    failed_poles = [
        (n, pr) for n, pr in pole_results.items() if pr.verdict == "failed"
    ]
    unavailable_poles = [
        (n, pr) for n, pr in pole_results.items() if pr.verdict == "unavailable"
    ]

    # Substance comparison: group ``ok`` poles by (height, observed_hash)
    # where the witness exposes those keys. Poles that do not expose
    # an ``observed_block_hash`` (the offline poles) are compared on
    # ``heights`` instead.
    hash_groups: dict[str, list[str]] = {}
    height_groups: dict[str, list[str]] = {}
    for name, pr in ok_poles:
        witness = dict(pr.witness)
        observed = witness.get("observed_block_hash")
        if isinstance(observed, str) and observed:
            hash_groups.setdefault(observed, []).append(name)
        heights = witness.get("heights")
        if isinstance(heights, list) and heights:
            key = ",".join(str(h) for h in heights)
            height_groups.setdefault(key, []).append(name)

    hash_disagreement = len(hash_groups) > 1
    height_disagreement = len(height_groups) > 1
    substance_disagreement = hash_disagreement or height_disagreement

    failed_count = len(failed_poles)
    severity: str
    if failed_count >= 2:
        severity = "brand-critical"
    elif failed_count >= 1 or substance_disagreement:
        severity = "substance"
    elif unavailable_poles:
        severity = "silent-minority"
    else:
        severity = "none"

    return {
        "severity": severity,
        "ok_poles": [n for n, _ in ok_poles],
        "failed_poles": [n for n, _ in failed_poles],
        "unavailable_poles": [n for n, _ in unavailable_poles],
        "hash_groups": hash_groups,
        "height_groups": height_groups,
        "hash_disagreement": hash_disagreement,
        "height_disagreement": height_disagreement,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _evaluate_overall(
    pole_results: Mapping[str, PoleResult],
    *,
    supporting_quorum: bool,
    mandatory_verified_by: tuple[str, ...],
) -> str:
    """Fold pole results into ``verified`` / ``failed`` / ``not_checked``.

    Order matters. A contradiction anywhere outranks everything else,
    because a verifier that saw a contradiction and reported a softer
    word would be doing the thing this module exists to stop. Absent
    a contradiction, a positive verdict needs a mandatory pole to have
    bound the root; supporting evidence alone yields ``not_checked``.
    """
    if not pole_results:
        return "not_checked"
    if any(pr.verdict == VERDICT_FAILED for pr in pole_results.values()):
        return "failed"
    if mandatory_verified_by and supporting_quorum:
        return "verified"
    return "not_checked"


def _evaluate_quorum(
    pole_results: Mapping[str, PoleResult],
    policy: QuorumPolicy,
) -> bool:
    """Raw ``ok``-count against the policy threshold.

    This is the *supporting* threshold only. It was the entire verdict
    until the 2026-09-14 re-review; it is now one of two conditions,
    and the weaker one.
    """
    ok_count = sum(1 for pr in pole_results.values() if pr.ok)
    total = len(pole_results)
    if total == 0:
        return False
    if policy == QuorumPolicy.ALL:
        return ok_count == total
    if policy == QuorumPolicy.THREE_OF_FOUR:
        return ok_count >= 3
    if policy == QuorumPolicy.TWO_OF_FOUR:
        return ok_count >= 2
    raise ValueError(f"unknown quorum policy: {policy}")  # pragma: no cover


def _is_hex_hash(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
    except ValueError:
        return False
    return s == s.lower()
