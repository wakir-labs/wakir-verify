# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Standalone WAT manifest reader for offline brand-proof verification.

This module is the MVP standalone reader for the
``wakir-wat-manifest/v1`` envelope shape that the real
hourly aggregator emits next to ``root.bin`` and ``root.bin.ots``
under archive paths like ``<archive>/<RUN>/<HOUR>/manifest.json``.

Scope (Cut-1 0.1.0)
-------------------

This is the *offline brand-proof* shape — minimum sufficient to load
a manifest from disk, expose its merkle root, leaf list and event
identifiers, and let the inclusion-check code in
:mod:`wakir_verify.merkle_proof` reconstruct a proof.

The exhaustive Draft-2020-12 schema validator for the
``wat-manifest/v2`` shape lives in ``wakir-runtime/wat/verify/
manifest_v2.py`` (BUSL-1.1, hosted-service substrate). That code is
not part of the Apache-2.0 brand-proof verifier in Cut-1. Cut-2
candidate if standalone offline validation of v2 manifests is
requested by external adopters.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence


@dataclasses.dataclass(frozen=True)
class ManifestLeaf:
    """A single manifest leaf in the canonical v1 envelope shape."""

    event_id: str
    leaf_hash: bytes

    def hex(self) -> str:
        return self.leaf_hash.hex()


@dataclasses.dataclass(frozen=True)
class Manifest:
    """In-memory representation of a WAT manifest envelope.

    Attributes
    ----------
    envelope:
        Free-form ``str`` identifier from the manifest's ``envelope``
        field, e.g. ``"wakir-wat-manifest/v1"``. Useful for routing
        between v1 and v2 readers in higher-level code.
    merkle_root:
        32-byte SHA-256 root recorded in the manifest.
    leaves:
        Ordered list of leaf entries.
    hour:
        Optional ISO-8601 hour bucket string (``YYYY-MM-DDTHH``).
    raw:
        The full manifest dictionary as read from disk, kept around so
        callers can read additional v1/v2 fields without re-parsing.
    """

    envelope: str
    merkle_root: bytes
    leaves: Sequence[ManifestLeaf]
    hour: Optional[str]
    raw: Mapping[str, Any]

    @property
    def leaf_hashes(self) -> List[bytes]:
        return [leaf.leaf_hash for leaf in self.leaves]

    def find_leaf(self, event_id: str) -> Optional[int]:
        """Return the 0-based leaf index for *event_id*, or None.

        Linear scan; manifests are bounded to ~thousands of leaves per
        hour in the deployed pipeline, so this is fine for offline
        verification.
        """
        for idx, leaf in enumerate(self.leaves):
            if leaf.event_id == event_id:
                return idx
        return None


class ManifestParseError(ValueError):
    """Raised when the manifest cannot be loaded into the v1 shape."""


def _expect_hex(value: Any, field: str, length_bytes: int) -> bytes:
    if not isinstance(value, str):
        raise ManifestParseError(
            f"manifest field '{field}' must be a hex string, "
            f"got {type(value).__name__}"
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ManifestParseError(
            f"manifest field '{field}' is not valid hex: {exc}"
        ) from exc
    if len(raw) != length_bytes:
        raise ManifestParseError(
            f"manifest field '{field}' must decode to {length_bytes} "
            f"bytes, got {len(raw)}"
        )
    return raw


def load_manifest_from_file(path: str | Path) -> Manifest:
    """Load a manifest JSON file from *path* into a :class:`Manifest`.

    Supports the ``wakir-wat-manifest/v1`` envelope shape with the
    common keys ``envelope``, ``merkle_root`` (32-byte hex),
    ``leaves`` (list of objects with at minimum ``event_id`` and
    ``leaf_hash``) and an optional ``hour`` string.
    """
    p = Path(path)
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError as exc:
        raise ManifestParseError(f"manifest not found at {p}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestParseError(
            f"manifest at {p} is not valid JSON: {exc}"
        ) from exc

    return load_manifest_from_dict(data)


def load_manifest_from_dict(data: Mapping[str, Any]) -> Manifest:
    """Load a manifest from an in-memory mapping (already-parsed JSON)."""
    if not isinstance(data, Mapping):
        raise ManifestParseError(
            "manifest top-level must be a JSON object"
        )

    envelope = str(data.get("envelope", ""))
    merkle_root = _expect_hex(data.get("merkle_root"), "merkle_root", 32)

    leaves_raw = data.get("leaves")
    if not isinstance(leaves_raw, list):
        raise ManifestParseError(
            "manifest field 'leaves' must be a list"
        )

    leaves: List[ManifestLeaf] = []
    for idx, leaf in enumerate(leaves_raw):
        if not isinstance(leaf, Mapping):
            raise ManifestParseError(
                f"manifest leaves[{idx}] must be a JSON object"
            )
        event_id = leaf.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise ManifestParseError(
                f"manifest leaves[{idx}].event_id missing or not a string"
            )
        leaf_hash = _expect_hex(
            leaf.get("leaf_hash"), f"leaves[{idx}].leaf_hash", 32
        )
        leaves.append(ManifestLeaf(event_id=event_id, leaf_hash=leaf_hash))

    hour = data.get("hour")
    if hour is not None and not isinstance(hour, str):
        raise ManifestParseError("manifest field 'hour' must be a string")

    return Manifest(
        envelope=envelope,
        merkle_root=merkle_root,
        leaves=leaves,
        hour=hour,
        raw=dict(data),
    )


def compute_manifest_consistency(manifest: Manifest) -> bool:
    """Cheap consistency check: re-fold leaves into a Bitcoin-pattern
    Merkle root and compare to the manifest's recorded root.

    Returns ``True`` if the root re-derives. Returns ``False`` (does
    not raise) on mismatch; callers should decide whether to log,
    fail, or surface the mismatch in a verifier report.

    Note: this is the *internal* consistency check. It says nothing
    about whether the manifest is anchored on Bitcoin. The OTS
    anchor check is in :mod:`wakir_verify.ots_verify`.
    """
    from wakir_verify.merkle_proof import root_hash

    if not manifest.leaves:
        return False
    leaves = [leaf.leaf_hash for leaf in manifest.leaves]
    derived = root_hash(leaves)
    return derived == manifest.merkle_root


__all__ = [
    "Manifest",
    "ManifestLeaf",
    "ManifestParseError",
    "load_manifest_from_file",
    "load_manifest_from_dict",
    "compute_manifest_consistency",
]
