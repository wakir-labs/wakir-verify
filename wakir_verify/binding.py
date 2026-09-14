# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Binding checks: from a hash list to statements about events.

:func:`wakir_verify.manifest.compute_manifest_consistency` folds the
leaf hashes a manifest **stores** into the root it **stores**. That is
arithmetic over the manifest's own assertions, and it is honest about
being that. The gap opens one level up, where a caller reads a green
consistency check as "the events are intact". They are two different
statements, and the external re-review of 2026-09-14 demonstrated the
distance between them: edit ``event_id`` and ``payload_hash`` in the
event records, leave the stored leaf hashes and the root alone, and
consistency stays positive while an independent recomputation of the
leaf hash no longer matches.

This module supplies the recomputation, in three strengths that are
never conflated because the evidence names which one ran:

``manifest-internal``
    Leaf hashes recomputed from the four B1 fields **the manifest
    itself carries** (``wakir-wat-manifest/v1`` writes all four per
    leaf). This catches the re-review's counter-example: the edited
    fields no longer hash to the stored leaf. It does not catch an
    edit that rewrites fields *and* leaf hashes *and* the root
    consistently — for that the root must be anchored, which is the
    ``root_authenticity`` claim's job, not this one's.

``external-events``
    Leaf hashes recomputed from event records supplied out of band
    (``--events``, the aggregator's own input shape: one JSON object
    per line carrying at least the four B1 fields). This binds the
    manifest to records that did not come from the manifest.

``payload``
    The bytes of an event's payload hashed and compared against the
    ``payload_hash`` the leaf commits to. Separate claim, because a
    digest is not its preimage: without the bytes, nothing about the
    content has been checked, and the report says so.

Scope note (carried into the PR as a finding rather than a change):
none of this needs a manifest v2. The four fields are already in the
v1 envelope; the verifier was discarding them at the door.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from wakir_verify.claims import (
    CLAIM_EVENT_BINDING,
    CLAIM_HASHLIST,
    CLAIM_PAYLOAD,
    Claim,
    STATUS_FAILED,
    STATUS_OK,
    not_checked,
)
from wakir_verify.manifest import Manifest, ManifestLeaf
from wakir_verify.merkle_proof import (
    _canonicalise,
    compute_leaf_hash,
    root_hash,
    verify_merkle_proof,
)

#: The four fields that go into a WAT leaf hash, in spec order
#: (``wirelang/specs/wat-leaf-projection.md`` §2, wakir-runtime).
B1_FIELDS = ("event_id", "time", "payload_hash", "capability_token_hash")

#: Schema identifier of the inclusion-proof artefact this module binds
#: against (``wirelang/schemas/wakir-inclusion-proof-v1.json``).
INCLUSION_PROOF_SCHEMA = "wakir-inclusion-proof/v1"

#: How many mismatching rows to name in evidence before truncating.
_MAX_REPORTED = 10


class EventInputError(ValueError):
    """Raised when an external event file cannot be read into records."""


# ---------------------------------------------------------------------------
# External event records
# ---------------------------------------------------------------------------


def load_events_from_file(path: str | Path) -> List[Dict[str, Any]]:
    """Load event records from JSONL or a JSON array.

    The hour spool writes one JSON object per line
    (``docs/wat-spool-spec.md`` §2, nine fields of which four are
    hash inputs); a JSON array of the same objects is accepted for
    convenience. Records are returned verbatim — this function does
    not fill in, normalise or repair fields. A verifier that repairs
    its own input is checking its repairs.
    """
    p = Path(path)
    try:
        text = p.read_text()
    except FileNotFoundError as exc:
        raise EventInputError(f"event file not found: {p}") from exc

    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise EventInputError(f"{p} is not valid JSON: {exc}") from exc
        if not isinstance(data, list):
            raise EventInputError(f"{p} must hold a JSON array of objects")
        records = data
    else:
        records = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise EventInputError(
                    f"{p} line {lineno} is not valid JSON: {exc}"
                ) from exc

    for idx, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise EventInputError(f"{p} record {idx} is not a JSON object")
    return [dict(r) for r in records]


def _recompute(fields: Mapping[str, Any]) -> Optional[bytes]:
    """Leaf hash from the four B1 fields, or None if one is missing.

    Missing is reported as missing. Substituting an empty string for an
    absent field would produce a hash, and a hash that happens not to
    match reads as tampering rather than as incomplete input.
    """
    values = []
    for field in B1_FIELDS:
        value = fields.get(field)
        if not isinstance(value, str):
            return None
        values.append(value)
    return compute_leaf_hash(*values)


# ---------------------------------------------------------------------------
# Claim 1 — hash-list consistency
# ---------------------------------------------------------------------------


def check_hashlist_consistency(manifest: Manifest) -> Claim:
    """Do the stored leaf hashes fold to the stored root?

    Deliberately narrow, and labelled as such: this is the claim the
    report must stop over-reading, not the one it must strengthen.
    """
    if not manifest.leaves:
        return Claim(
            name=CLAIM_HASHLIST,
            status=STATUS_FAILED,
            summary="manifest carries no leaves, so no root can be derived",
            evidence={"leaf_count": 0},
        )

    derived = root_hash([leaf.leaf_hash for leaf in manifest.leaves])
    ok = derived == manifest.merkle_root
    return Claim(
        name=CLAIM_HASHLIST,
        status=STATUS_OK if ok else STATUS_FAILED,
        summary=(
            "the stored leaf hashes fold to the stored Merkle root "
            "(this says nothing about the events themselves)"
            if ok
            else "the stored leaf hashes do not fold to the stored root"
        ),
        evidence={
            "leaf_count": len(manifest.leaves),
            "recorded_root": manifest.merkle_root.hex(),
            "derived_root": derived.hex(),
        },
    )


# ---------------------------------------------------------------------------
# Claim 2 — event binding
# ---------------------------------------------------------------------------


def check_event_binding(
    manifest: Manifest,
    *,
    events: Optional[Sequence[Mapping[str, Any]]] = None,
    proof: Optional[Mapping[str, Any]] = None,
    target_event_id: Optional[str] = None,
) -> Claim:
    """Do the recorded event fields re-derive the stored leaf hashes?

    Runs the strongest recomputation the inputs allow and says which
    one that was. When ``events`` is given, every manifest leaf must
    have exactly one matching external record and that record's fields
    must reproduce the stored leaf hash; a leaf with no record, or an
    ``event_id`` appearing twice, is a failure rather than a skip.

    When ``proof`` is given, the inclusion proof must belong to *this*
    manifest: matching root, an in-range index, the leaf hash the
    manifest holds at that index, a consistent ``event_id``, and a
    sibling path that reconstructs the root. A proof for some other
    manifest is a failure here, which is the point — it is exactly the
    substitution an unbound proof artefact invites.
    """
    evidence: Dict[str, Any] = {"leaf_count": len(manifest.leaves)}

    if not manifest.leaves:
        return Claim(
            name=CLAIM_EVENT_BINDING,
            status=STATUS_FAILED,
            summary="manifest carries no leaves to bind",
            evidence=evidence,
        )

    if events is not None:
        result = _bind_against_external_events(manifest, events)
    else:
        result = _bind_against_manifest_fields(manifest)
    evidence.update(result["evidence"])
    status = result["status"]
    summary = result["summary"]

    if proof is not None:
        proof_result = _bind_proof_to_manifest(
            manifest, proof, target_event_id=target_event_id
        )
        evidence["proof_binding"] = proof_result["evidence"]
        if proof_result["status"] == STATUS_FAILED:
            status = STATUS_FAILED
            summary = proof_result["summary"]
        elif status == STATUS_OK and proof_result["status"] != STATUS_OK:
            status = proof_result["status"]
            summary = proof_result["summary"]
    elif target_event_id is not None:
        idx = manifest.find_leaf(target_event_id)
        evidence["target_event_id"] = target_event_id
        evidence["target_leaf_index"] = idx
        if idx is None:
            status = STATUS_FAILED
            summary = (
                f"target event {target_event_id!r} is not in this manifest"
            )

    return Claim(
        name=CLAIM_EVENT_BINDING,
        status=status,
        summary=summary,
        evidence=evidence,
    )


def _bind_against_manifest_fields(manifest: Manifest) -> Dict[str, Any]:
    """Recompute leaf hashes from the manifest's own B1 fields."""
    with_fields = [leaf for leaf in manifest.leaves if leaf.has_event_fields]
    if not with_fields:
        return {
            "status": not_checked(CLAIM_EVENT_BINDING, "").status,
            "summary": (
                "event binding not checked: this manifest carries no event "
                "fields, only leaf hashes, and no --events file was supplied"
            ),
            "evidence": {
                "source": "none",
                "leaves_with_event_fields": 0,
            },
        }

    mismatches = _collect_mismatches(
        (leaf, _leaf_fields(leaf)) for leaf in with_fields
    )
    incomplete = len(manifest.leaves) - len(with_fields)
    evidence = {
        "source": "manifest-internal",
        "leaves_with_event_fields": len(with_fields),
        "leaves_without_event_fields": incomplete,
        "mismatches": mismatches[:_MAX_REPORTED],
        "mismatch_count": len(mismatches),
    }
    if mismatches:
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"{len(mismatches)} of {len(with_fields)} leaves do not "
                "re-derive from their own recorded event fields"
            ),
            "evidence": evidence,
        }
    if incomplete:
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"{incomplete} of {len(manifest.leaves)} leaves carry no "
                "event fields, so their hashes rest on nothing checkable"
            ),
            "evidence": evidence,
        }
    return {
        "status": STATUS_OK,
        "summary": (
            f"all {len(with_fields)} leaf hashes re-derive from the event "
            "fields recorded in this manifest (manifest-internal: the "
            "fields and the hashes come from the same file; --events binds "
            "against records from outside it)"
        ),
        "evidence": evidence,
    }


def _bind_against_external_events(
    manifest: Manifest,
    events: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Recompute leaf hashes from event records supplied out of band."""
    by_id: Dict[str, Mapping[str, Any]] = {}
    duplicates: List[str] = []
    for record in events:
        event_id = record.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            continue
        if event_id in by_id:
            duplicates.append(event_id)
            continue
        by_id[event_id] = record

    missing: List[str] = []
    pairs = []
    for leaf in manifest.leaves:
        record = by_id.get(leaf.event_id)
        if record is None:
            missing.append(leaf.event_id)
            continue
        pairs.append((leaf, dict(record)))

    mismatches = _collect_mismatches(pairs)
    evidence = {
        "source": "external-events",
        "event_records": len(events),
        "matched": len(pairs),
        "missing_event_ids": missing[:_MAX_REPORTED],
        "missing_count": len(missing),
        "duplicate_event_ids": duplicates[:_MAX_REPORTED],
        "mismatches": mismatches[:_MAX_REPORTED],
        "mismatch_count": len(mismatches),
    }

    problems = []
    if mismatches:
        problems.append(
            f"{len(mismatches)} leaf hash(es) do not re-derive from the "
            "supplied event records"
        )
    if missing:
        problems.append(
            f"{len(missing)} manifest leaf/leaves have no matching event "
            "record"
        )
    if duplicates:
        problems.append(
            f"{len(duplicates)} event_id(s) appear more than once, so the "
            "leaf-to-event mapping is not unique"
        )
    if problems:
        return {
            "status": STATUS_FAILED,
            "summary": "; ".join(problems),
            "evidence": evidence,
        }
    return {
        "status": STATUS_OK,
        "summary": (
            f"all {len(pairs)} leaf hashes re-derive from event records "
            "supplied independently of the manifest"
        ),
        "evidence": evidence,
    }


def _leaf_fields(leaf: ManifestLeaf) -> Dict[str, Any]:
    return {
        "event_id": leaf.event_id,
        "time": leaf.time,
        "payload_hash": leaf.payload_hash,
        "capability_token_hash": leaf.capability_token_hash,
    }


def _collect_mismatches(pairs) -> List[Dict[str, Any]]:
    """Leaves whose recorded fields do not reproduce the stored hash."""
    out: List[Dict[str, Any]] = []
    for leaf, fields in pairs:
        recomputed = _recompute(fields)
        if recomputed is None:
            out.append(
                {
                    "event_id": leaf.event_id,
                    "stored_leaf_hash": leaf.hex(),
                    "recomputed_leaf_hash": None,
                    "reason": "record is missing one of the four B1 fields",
                }
            )
            continue
        if recomputed != leaf.leaf_hash:
            out.append(
                {
                    "event_id": leaf.event_id,
                    "stored_leaf_hash": leaf.hex(),
                    "recomputed_leaf_hash": recomputed.hex(),
                    "reason": "recomputed leaf hash differs from stored",
                }
            )
    return out


def _bind_proof_to_manifest(
    manifest: Manifest,
    proof: Mapping[str, Any],
    *,
    target_event_id: Optional[str],
) -> Dict[str, Any]:
    """Check an inclusion proof belongs to this manifest and this event."""
    evidence: Dict[str, Any] = {"schema": proof.get("schema")}

    if proof.get("schema") != INCLUSION_PROOF_SCHEMA:
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"inclusion proof schema {proof.get('schema')!r} is not "
                f"{INCLUSION_PROOF_SCHEMA!r}"
            ),
            "evidence": evidence,
        }

    proof_root = str(proof.get("merkle_root", "")).lower()
    evidence["proof_merkle_root"] = proof_root
    evidence["manifest_merkle_root"] = manifest.merkle_root.hex()
    if proof_root != manifest.merkle_root.hex():
        return {
            "status": STATUS_FAILED,
            "summary": (
                "the inclusion proof is for a different manifest: its root "
                f"{proof_root} is not this manifest's "
                f"{manifest.merkle_root.hex()}"
            ),
            "evidence": evidence,
        }

    index = proof.get("leaf_index")
    evidence["leaf_index"] = index
    if not isinstance(index, int) or not 0 <= index < len(manifest.leaves):
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"inclusion-proof leaf_index {index!r} is outside this "
                f"manifest's {len(manifest.leaves)} leaves"
            ),
            "evidence": evidence,
        }

    leaf = manifest.leaves[index]
    proof_leaf = str(proof.get("leaf_hash", "")).lower()
    evidence["proof_leaf_hash"] = proof_leaf
    evidence["manifest_leaf_hash"] = leaf.hex()
    evidence["manifest_event_id"] = leaf.event_id
    if proof_leaf != leaf.hex():
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"the proof's leaf hash is not the manifest's leaf at index "
                f"{index}"
            ),
            "evidence": evidence,
        }

    proof_event_id = proof.get("event_id")
    if isinstance(proof_event_id, str) and proof_event_id != leaf.event_id:
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"the proof names event {proof_event_id!r} but index {index} "
                f"of this manifest is {leaf.event_id!r}"
            ),
            "evidence": evidence,
        }

    wanted = target_event_id or proof_event_id
    if isinstance(wanted, str) and wanted != leaf.event_id:
        return {
            "status": STATUS_FAILED,
            "summary": (
                f"the proof does not cover the requested event {wanted!r}"
            ),
            "evidence": evidence,
        }

    siblings_raw = proof.get("siblings")
    if not isinstance(siblings_raw, list):
        return {
            "status": STATUS_FAILED,
            "summary": "inclusion proof has no sibling list",
            "evidence": evidence,
        }
    try:
        siblings = [
            (bytes.fromhex(str(s["hash"])), str(s["side"]))
            for s in siblings_raw
        ]
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "status": STATUS_FAILED,
            "summary": f"inclusion proof sibling list is malformed: {exc}",
            "evidence": evidence,
        }

    reconstructs = verify_merkle_proof(
        leaf.leaf_hash, siblings, manifest.merkle_root
    )
    evidence["path_reconstructs_root"] = reconstructs
    evidence["sibling_count"] = len(siblings)
    if not reconstructs:
        return {
            "status": STATUS_FAILED,
            "summary": (
                "the inclusion proof's sibling path does not reconstruct "
                "the manifest root"
            ),
            "evidence": evidence,
        }

    return {
        "status": STATUS_OK,
        "summary": (
            f"the inclusion proof binds event {leaf.event_id!r} at index "
            f"{index} to this manifest's root"
        ),
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Claim 3 — payload check
# ---------------------------------------------------------------------------


def check_payload_binding(
    manifest: Manifest,
    payloads: Optional[Mapping[str, bytes]] = None,
) -> Claim:
    """Do supplied payload bytes hash to the committed ``payload_hash``?

    ``payloads`` maps ``event_id`` to the raw bytes of that event's
    Wirelang ``data`` slot as JSON. The projection spec defines
    ``payload_hash = SHA-256(JCS(data))`` over the *parsed* value, not
    over the bytes as they arrived, so the bytes are parsed and
    re-canonicalised here; a whitespace difference is not tampering and
    must not be reported as such. Bytes that are not JSON are hashed
    verbatim as a fallback and the evidence records which of the two
    routes matched.

    Without payloads the claim is ``not_checked``. The audit trail
    commits to a digest; the digest does not carry its preimage, and
    no amount of manifest checking can conjure one.
    """
    if not payloads:
        return not_checked(
            CLAIM_PAYLOAD,
            "payload contents not checked: no payload bytes were supplied",
            payloads_supplied=0,
        )

    by_id = {leaf.event_id: leaf for leaf in manifest.leaves}
    results: List[Dict[str, Any]] = []
    failures = 0
    for event_id, raw in payloads.items():
        leaf = by_id.get(event_id)
        if leaf is None:
            results.append(
                {
                    "event_id": event_id,
                    "status": STATUS_FAILED,
                    "reason": "event is not in this manifest",
                }
            )
            failures += 1
            continue
        if leaf.payload_hash is None:
            results.append(
                {
                    "event_id": event_id,
                    "status": STATUS_FAILED,
                    "reason": (
                        "manifest leaf records no payload_hash to compare "
                        "against"
                    ),
                }
            )
            failures += 1
            continue

        canonical_digest, mode = _payload_digest(raw)
        ok = canonical_digest == leaf.payload_hash.lower()
        results.append(
            {
                "event_id": event_id,
                "status": STATUS_OK if ok else STATUS_FAILED,
                "mode": mode,
                "committed_payload_hash": leaf.payload_hash.lower(),
                "computed_payload_hash": canonical_digest,
            }
        )
        if not ok:
            failures += 1

    return Claim(
        name=CLAIM_PAYLOAD,
        status=STATUS_FAILED if failures else STATUS_OK,
        summary=(
            f"{failures} of {len(results)} supplied payload(s) do not hash "
            "to the committed payload_hash"
            if failures
            else f"all {len(results)} supplied payload(s) hash to the "
            "payload_hash their leaf commits to"
        ),
        evidence={"payloads": results, "checked": len(results)},
    )


def _payload_digest(raw: bytes) -> tuple[str, str]:
    """Return ``(hex digest, mode)`` for payload bytes.

    Prefers the spec route — parse as JSON, canonicalise per RFC 8785,
    hash — and falls back to hashing the bytes verbatim so a non-JSON
    payload still gets a comparable digest instead of an exception.
    """
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return hashlib.sha256(raw).hexdigest(), "raw-bytes"
    return hashlib.sha256(_canonicalise(parsed)).hexdigest(), "jcs"


__all__ = [
    "B1_FIELDS",
    "EventInputError",
    "INCLUSION_PROOF_SCHEMA",
    "check_event_binding",
    "check_hashlist_consistency",
    "check_payload_binding",
    "load_events_from_file",
]
