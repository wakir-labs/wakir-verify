# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""MVP tests for the standalone manifest reader."""

from __future__ import annotations

import json

import pytest

from wakir_verify.manifest import (
    Manifest,
    ManifestLeaf,
    ManifestParseError,
    compute_manifest_consistency,
    load_manifest_from_dict,
    load_manifest_from_file,
)
from wakir_verify.merkle_proof import compute_inner_hash, leaf_hash


def _three_leaf_manifest_dict() -> dict:
    """Build a tiny but Merkle-consistent 3-leaf manifest dict."""
    leaves_canonical = [b'{"i":0}', b'{"i":1}', b'{"i":2}']
    h = [leaf_hash(c) for c in leaves_canonical]
    # 3 leaves -> duplicate last on level 0 to pair, then duplicate
    # the right node on level 1.
    l01 = compute_inner_hash(h[0], h[1])
    l23 = compute_inner_hash(h[2], h[2])
    root = compute_inner_hash(l01, l23)
    return {
        "envelope": "wakir-wat-manifest/v1",
        "hour": "2026-05-16T11",
        "merkle_root": root.hex(),
        "leaves": [
            {"event_id": f"evt-{i}", "leaf_hash": h[i].hex()}
            for i in range(3)
        ],
    }


def test_load_manifest_from_dict_happy_path():
    data = _three_leaf_manifest_dict()
    m = load_manifest_from_dict(data)
    assert isinstance(m, Manifest)
    assert m.envelope == "wakir-wat-manifest/v1"
    assert m.hour == "2026-05-16T11"
    assert len(m.leaves) == 3
    assert all(isinstance(l, ManifestLeaf) for l in m.leaves)
    assert m.find_leaf("evt-1") == 1
    assert m.find_leaf("evt-does-not-exist") is None


def test_load_manifest_from_file_reads_json(tmp_path):
    data = _three_leaf_manifest_dict()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    m = load_manifest_from_file(path)
    assert len(m.leaves) == 3


def test_load_manifest_rejects_invalid_root_length():
    data = _three_leaf_manifest_dict()
    data["merkle_root"] = "deadbeef"  # not 64 hex chars
    with pytest.raises(ManifestParseError):
        load_manifest_from_dict(data)


def test_load_manifest_rejects_non_string_event_id():
    data = _three_leaf_manifest_dict()
    data["leaves"][0]["event_id"] = 42
    with pytest.raises(ManifestParseError):
        load_manifest_from_dict(data)


def test_load_manifest_missing_file_raises(tmp_path):
    with pytest.raises(ManifestParseError):
        load_manifest_from_file(tmp_path / "nope.json")


def test_load_manifest_invalid_json_raises(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{ not json")
    with pytest.raises(ManifestParseError):
        load_manifest_from_file(path)


def test_compute_manifest_consistency_passes_for_real_root():
    data = _three_leaf_manifest_dict()
    m = load_manifest_from_dict(data)
    assert compute_manifest_consistency(m) is True


def test_compute_manifest_consistency_fails_on_wrong_root():
    data = _three_leaf_manifest_dict()
    # Flip a byte in the root
    bad = bytearray.fromhex(data["merkle_root"])
    bad[0] ^= 0xFF
    data["merkle_root"] = bad.hex()
    m = load_manifest_from_dict(data)
    assert compute_manifest_consistency(m) is False
