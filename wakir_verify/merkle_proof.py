# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors
#
# Merkle-Proof Read-Half for Wakir Audit Trail (WAT) verification.
# Re-classified from BUSL-1.1 to Apache-2.0 in ADR-0062 Cut-1
# (Brand-Beweis-Werkzeug). See wakir-runtime/docs/decisions/
# cut1-verifier-substance-classification.md.

"""Hourly Merkle aggregator for WAT.

In-house Bitcoin-pattern Merkle tree implementation. Drop-in for
hourly aggregation of Wirelang frame events.

Algorithm
---------

- Hash function: SHA-256 (FIPS 180-4 / RFC 6234), via stdlib hashlib.
- Leaf hash: SHA-256 over the JCS-canonicalised four-tuple
  ``(event_id, time, payload_hash, capability_token_hash)`` per the
  B1 cross-review consensus marker. JCS = RFC 8785.
- Internal node: SHA-256(left || right).
- Padding: when a level has an odd node count, the last node is
  duplicated (Bitcoin convention) so the level remains balanced.
- Output: 32-byte root digest plus the full level list when callers
  need to derive inclusion proofs.

Library decision (Phase 1a, day 1 compatibility check)
------------------------------------------------------

merkletools 1.0.3 (PyPI, MIT) — fails to build under Python 3.14
(depends on pysha3, whose C extension does not compile against
modern CPython headers).

pymerkle 6.1.0 (PyPI, GPLv3+) — installs cleanly but is
license-incompatible with BSL 1.1 module distribution.

Resulting plan: small in-house implementation with stdlib hashlib
only, lands here. JCS canonicalisation uses Trail of Bits'
``rfc8785`` (Apache-2.0, license-compatible) as a thin dependency;
fallback to a minimal in-tree canonicaliser is documented below
but not used by default.

Edge cases
----------

- Empty leaf list: ValueError. A receipt with zero events is not
  meaningful for the audit-trail use case; callers should skip the
  hour rather than anchor an empty root.
- One leaf: the root equals that single leaf hash (no duplication).
- Two leaves: standard hash(left || right).
- Odd intermediate level size: duplicate last node before pairing.
"""

from __future__ import annotations

import hashlib
import json
from typing import List, Sequence, Tuple

try:  # pragma: no cover - import-time fallback
    import rfc8785  # type: ignore
    _HAS_RFC8785 = True
except ImportError:  # pragma: no cover
    _HAS_RFC8785 = False


# Direction markers used in inclusion proofs. The sibling either sits
# to the LEFT or RIGHT of the current node when concatenating for the
# next-level hash.
DIR_LEFT = "L"
DIR_RIGHT = "R"


def _canonicalise(obj: object) -> bytes:
    """Return the JCS (RFC 8785) canonical UTF-8 encoding of ``obj``.

    Uses ``rfc8785`` from PyPI when available (Apache-2.0, Trail of
    Bits). Falls back to a minimal in-tree canonicaliser that
    sort-keys, encodes UTF-8, and emits no whitespace; this fallback
    is sufficient for the strict subset we need (string fields only)
    but does not implement RFC 8785 number-serialisation rules.
    """
    if _HAS_RFC8785:
        return rfc8785.dumps(obj)
    # Minimal subset: string-only fields, sorted keys, no whitespace.
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_leaf_hash(
    event_id: str,
    time: str,
    payload_hash: str,
    capability_token_hash: str,
) -> bytes:
    """Compute the SHA-256 leaf hash for a single audit-trail event.

    The inputs map onto the B1 cross-review four-field tuple. All
    four fields are required and serialised through JCS so that two
    independent implementations produce byte-identical leaf hashes
    given the same event.

    Parameters
    ----------
    event_id:
        Stable event identifier (Wirelang ``event_id``).
    time:
        RFC 3339 / ISO 8601 timestamp string.
    payload_hash:
        Hex-encoded digest of the event payload.
    capability_token_hash:
        Hex-encoded digest of the capability token used for the
        action; empty string is permitted for non-capability events
        but must still be passed explicitly to keep the leaf shape
        stable.

    Returns
    -------
    bytes
        32-byte SHA-256 digest of the canonicalised tuple.
    """
    tuple_obj = {
        "event_id": event_id,
        "time": time,
        "payload_hash": payload_hash,
        "capability_token_hash": capability_token_hash,
    }
    return _sha256(_canonicalise(tuple_obj))


def compute_inner_hash(left: bytes, right: bytes) -> bytes:
    """Compute the SHA-256 hash of two concatenated child hashes."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("inner hash inputs must each be 32 bytes")
    return _sha256(left + right)


def build_merkle_tree(
    leaves: Sequence[bytes],
) -> Tuple[bytes, List[List[bytes]]]:
    """Build a Bitcoin-pattern Merkle tree.

    Parameters
    ----------
    leaves:
        Sequence of 32-byte leaf hashes, in the order they should
        appear at level 0. The caller is responsible for the
        ordering convention (e.g. lexicographic by event_id).

    Returns
    -------
    tuple
        ``(root_hash, levels)`` where ``levels[0]`` is the leaves
        list (post-duplication if any) and ``levels[-1]`` is a
        single-element list holding the root. For a single-leaf
        tree the root equals that leaf and ``levels`` has length 1.

    Raises
    ------
    ValueError
        If ``leaves`` is empty or any leaf is not exactly 32 bytes.
    """
    if not leaves:
        raise ValueError("cannot build a Merkle tree from zero leaves")
    for idx, leaf in enumerate(leaves):
        if len(leaf) != 32:
            raise ValueError(f"leaf {idx} is {len(leaf)} bytes, expected 32")

    levels: List[List[bytes]] = [list(leaves)]

    current = list(leaves)
    while len(current) > 1:
        if len(current) % 2 == 1:
            # Bitcoin convention: duplicate the last element.
            current = current + [current[-1]]
        nxt: List[bytes] = []
        for i in range(0, len(current), 2):
            nxt.append(compute_inner_hash(current[i], current[i + 1]))
        # Record the post-duplication current level so the recorded
        # tree faithfully reflects what was hashed at each step.
        levels[-1] = current
        levels.append(nxt)
        current = nxt

    return current[0], levels


def merkle_proof(
    leaves: Sequence[bytes],
    leaf_index: int,
) -> List[Tuple[bytes, str]]:
    """Build an inclusion proof for ``leaves[leaf_index]``.

    Parameters
    ----------
    leaves:
        Same leaf list passed to ``build_merkle_tree``.
    leaf_index:
        Zero-based index of the leaf the caller wants a proof for.

    Returns
    -------
    list of (sibling_hash, direction)
        Bottom-up list of sibling hashes plus a direction marker
        (``"L"`` if the sibling sits to the left of the current
        node, ``"R"`` if it sits to the right). Empty for a
        single-leaf tree.

    Raises
    ------
    IndexError
        If ``leaf_index`` is out of range.
    ValueError
        Propagated from ``build_merkle_tree``.
    """
    if leaf_index < 0 or leaf_index >= len(leaves):
        raise IndexError(f"leaf_index {leaf_index} out of range for {len(leaves)} leaves")

    _, levels = build_merkle_tree(leaves)

    proof: List[Tuple[bytes, str]] = []
    idx = leaf_index
    for level in levels[:-1]:
        # Padding may have grown this level after build; mirror it
        # here so sibling lookup matches the hash that was produced.
        if idx ^ 1 < len(level):
            sibling_idx = idx ^ 1
        else:
            # Right edge with duplicated last node: sibling is self.
            sibling_idx = idx
        sibling = level[sibling_idx]
        direction = DIR_LEFT if sibling_idx < idx else DIR_RIGHT
        proof.append((sibling, direction))
        idx //= 2

    return proof


def verify_merkle_proof(
    leaf_hash: bytes,
    proof: Sequence[Tuple[bytes, str]],
    root: bytes,
) -> bool:
    """Verify an inclusion proof against a known Merkle root.

    Parameters
    ----------
    leaf_hash:
        The 32-byte leaf hash whose membership is being proven.
    proof:
        Output of :func:`merkle_proof` for that leaf.
    root:
        The 32-byte Merkle root to verify against.

    Returns
    -------
    bool
        True iff the proof reconstructs to ``root``.
    """
    if len(leaf_hash) != 32 or len(root) != 32:
        return False
    current = leaf_hash
    for sibling, direction in proof:
        if len(sibling) != 32:
            return False
        if direction == DIR_LEFT:
            current = compute_inner_hash(sibling, current)
        elif direction == DIR_RIGHT:
            current = compute_inner_hash(current, sibling)
        else:
            return False
    return current == root


# ---------------------------------------------------------------------------
# Backwards-compatible thin wrappers preserved from the day-1 skeleton so
# that downstream callers wired against the old signatures keep working.
# ---------------------------------------------------------------------------


def leaf_hash(canonical_bytes: bytes) -> bytes:
    """Return SHA-256 of pre-canonicalised leaf bytes.

    Convenience for callers that have already canonicalised their
    leaf payload (e.g. JCS-encoded a non-WAT shape). Most callers
    should prefer :func:`compute_leaf_hash` which enforces the
    four-field WAT shape.
    """
    return _sha256(canonical_bytes)


def root_hash(leaves: Sequence[bytes]) -> bytes:
    """Compute only the Merkle root, discarding intermediate levels."""
    root, _levels = build_merkle_tree(list(leaves))
    return root
