# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Manifest loader compatibility pin: runtime emitter vs. verify loader.

``wakir-runtime`` (``wat/cmd/aggregator_cli.py``) writes the hour
manifest with the top-level keys ``version`` and ``hour_slot``.
``wakir_verify.manifest.load_manifest_from_file`` reads ``envelope``
and ``hour`` — both optional — and never looks at ``version`` or
``hour_slot``. The loader therefore *accepts* a runtime manifest, but
``Manifest.envelope`` comes back as ``""`` and ``Manifest.hour`` as
``None``; the runtime values remain reachable only through
``Manifest.raw``.

This is a known compatibility constraint (ADR-0072 Phase 4, sub-item
4c). It is pinned here on purpose so that either side changing its
field names — or the loader starting to honour the runtime names —
shows up as a red test rather than as a silent behaviour change. The
proof-path pieces that matter for the demo (``merkle_root``,
``leaves[].event_id``, ``leaves[].leaf_hash``, consistency) are
identical for both shapes and are asserted identical.

``RUNTIME_TO_LOADER_FIELDS`` is the documented constant; keep it in
sync with ``docs/quality-gates.md``.

Since protocol ``aeba192`` every proof-path vector embeds a real
``manifest`` in runtime aggregator form. Those are loaded under the same
pin below, and the synthetic ``_runtime_shape`` mirror (``build_time``
taken from the vector) is asserted equal to the embedded manifest so the
two cannot drift apart unnoticed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest

from wakir_verify.manifest import (
    Manifest,
    compute_manifest_consistency,
    load_manifest_from_dict,
    load_manifest_from_file,
)

#: Runtime manifest key -> the verify-loader key carrying the same
#: meaning. The loader does not translate between them today.
RUNTIME_TO_LOADER_FIELDS: Dict[str, str] = {
    "version": "envelope",
    "hour_slot": "hour",
}

#: Value the runtime writes into ``version`` (``MANIFEST_VERSION`` in
#: ``wat/cmd/aggregator_cli.py``) and the verify loader expects to see
#: in ``envelope`` when a manifest is written in loader-native shape.
MANIFEST_VERSION = "wakir-wat-manifest/v1"

RUNTIME_MANIFEST_ENV = "WAKIR_RUNTIME_MANIFEST"

HERMETIC_DIR = Path(__file__).resolve().parent / "fixtures" / "proof-path-vectors"
VECTOR_FILES = ("vector-1.json", "vector-2.json", "vector-3.json")


def _vector(name: str = "vector-2.json") -> Dict[str, Any]:
    return json.loads((HERMETIC_DIR / name).read_text(encoding="utf-8"))


def _runtime_shape(vec: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror ``wat/cmd/aggregator_cli.py::_build_manifest_object``."""
    rows = [
        {**leaf, "leaf_hash": leaf_hash}
        for leaf, leaf_hash in zip(vec["leaves"], vec["leaf_hashes"])
    ]
    return {
        "version": MANIFEST_VERSION,
        "hour_slot": vec["proofs"][0]["hour"],
        "merkle_root": vec["merkle_root"],
        "event_count": len(rows),
        "events": rows,
        "leaves": rows,
        "tree_levels": vec["levels"],
        "build_time": vec["manifest"]["build_time"],
        "prev_hour_root": None,
    }


def _loader_shape(vec: Dict[str, Any]) -> Dict[str, Any]:
    """The shape ``wakir_verify.manifest`` documents as native."""
    return {
        "envelope": MANIFEST_VERSION,
        "hour": vec["proofs"][0]["hour"],
        "merkle_root": vec["merkle_root"],
        "leaves": [
            {"event_id": leaf["event_id"], "leaf_hash": leaf_hash}
            for leaf, leaf_hash in zip(vec["leaves"], vec["leaf_hashes"])
        ],
    }


def _proof_relevant_view(m: Manifest) -> Dict[str, Any]:
    return {
        "merkle_root": m.merkle_root.hex(),
        "leaves": [(leaf.event_id, leaf.hex()) for leaf in m.leaves],
        "consistent": compute_manifest_consistency(m),
    }


def test_field_map_is_the_documented_constant() -> None:
    assert RUNTIME_TO_LOADER_FIELDS == {"version": "envelope", "hour_slot": "hour"}


def test_loader_accepts_both_shapes_with_identical_proof_view() -> None:
    vec = _vector()
    runtime = load_manifest_from_dict(_runtime_shape(vec))
    native = load_manifest_from_dict(_loader_shape(vec))
    assert _proof_relevant_view(runtime) == _proof_relevant_view(native)
    assert _proof_relevant_view(runtime)["consistent"] is True
    assert runtime.find_leaf(vec["leaves"][2]["event_id"]) == 2


def test_runtime_shape_pins_untranslated_envelope_and_hour() -> None:
    """Pin the constraint itself: runtime names are not mapped."""
    vec = _vector()
    runtime = load_manifest_from_dict(_runtime_shape(vec))
    native = load_manifest_from_dict(_loader_shape(vec))

    assert native.envelope == MANIFEST_VERSION
    assert native.hour == vec["proofs"][0]["hour"]

    # Constraint: the loader ignores the runtime names ...
    assert runtime.envelope == ""
    assert runtime.hour is None
    # ... but the values survive untouched in ``raw``.
    for runtime_key, loader_key in RUNTIME_TO_LOADER_FIELDS.items():
        assert runtime.raw[runtime_key] == getattr(native, loader_key)


def test_runtime_leaf_rows_carry_full_four_tuple_plus_leaf_hash() -> None:
    """The runtime row shape is a superset of what the loader needs."""
    vec = _vector()
    row = _runtime_shape(vec)["leaves"][0]
    assert set(row) == {"event_id", "time", "payload_hash", "capability_token_hash", "leaf_hash"}
    loaded = load_manifest_from_dict(_runtime_shape(vec))
    assert loaded.leaves[0].event_id == row["event_id"]
    assert loaded.leaves[0].hex() == row["leaf_hash"]


@pytest.mark.parametrize("name", VECTOR_FILES)
def test_synthetic_runtime_shape_equals_embedded_vector_manifest(name: str) -> None:
    """The local mirror of ``_build_manifest_object`` must match protocol."""
    vec = _vector(name)
    assert _runtime_shape(vec) == vec["manifest"]


@pytest.mark.parametrize("name", VECTOR_FILES)
def test_embedded_vector_manifest_loads_under_the_pin(name: str) -> None:
    """Same pin against the manifest protocol embeds in each vector."""
    vec = _vector(name)
    blob = vec["manifest"]
    for runtime_key in RUNTIME_TO_LOADER_FIELDS:
        assert runtime_key in blob, f"{name}: embedded manifest lacks {runtime_key!r}"
    assert blob["version"] == MANIFEST_VERSION

    m = load_manifest_from_dict(blob)
    assert compute_manifest_consistency(m) is True
    assert m.merkle_root.hex() == vec["merkle_root"]
    assert [leaf.hex() for leaf in m.leaves] == vec["leaf_hashes"]
    assert [leaf.event_id for leaf in m.leaves] == [row["event_id"] for row in vec["leaves"]]
    assert m.envelope == "" and m.hour is None  # the pinned constraint
    assert m.raw["version"] == MANIFEST_VERSION
    assert m.raw["hour_slot"] == blob["hour_slot"]
    assert len(m.leaves) == blob["event_count"]
    for doc in vec["proofs"]:
        assert doc["hour"] == blob["hour_slot"]
        assert m.find_leaf(doc["event_id"]) == doc["leaf_index"]


def test_real_runtime_manifest_from_demo_proof_loads_under_the_pin() -> None:
    """Same pin against the manifest ``make demo-proof`` actually wrote.

    The compat workflow exports ``WAKIR_RUNTIME_MANIFEST`` pointing at
    ``$DEMO_PROOF_WORKDIR/<hour>/manifest.json``; locally the test is
    skipped with a reason.
    """
    raw_path = os.environ.get(RUNTIME_MANIFEST_ENV)
    if not raw_path:
        pytest.skip(
            f"no runtime-produced manifest; set {RUNTIME_MANIFEST_ENV} "
            "(compat workflow does after make demo-proof)"
        )
    path = Path(raw_path)
    assert path.is_file(), path
    blob = json.loads(path.read_text(encoding="utf-8"))
    for runtime_key in RUNTIME_TO_LOADER_FIELDS:
        assert runtime_key in blob, f"runtime manifest lost field {runtime_key!r}"
    assert blob["version"] == MANIFEST_VERSION

    m = load_manifest_from_file(path)
    assert compute_manifest_consistency(m) is True
    assert m.envelope == "" and m.hour is None  # the pinned constraint
    assert m.raw["version"] == MANIFEST_VERSION
    assert m.raw["hour_slot"] == blob["hour_slot"]
    assert len(m.leaves) == blob["event_count"] >= 1
