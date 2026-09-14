# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Cross-repo proof-path vector tests (ADR-0072 Phase 4, sub-item 4c).

The canonical vectors live in wakir-protocol under
``tests/fixtures/proof-path-vectors/vector-{1,2,3}.json``. This module
drives ``wakir_verify.merkle_proof`` against them from two sources:

* **hermetic** — the copy checked into this repository under
  ``tests/fixtures/proof-path-vectors/``. Always runs (plain ``pytest``,
  the ``ci`` workflow).
* **protocol** — a checkout of wakir-protocol whose root is passed via
  ``WAKIR_PROTOCOL_CHECKOUT``. Runs in the ``compat`` workflow against
  ``protocol@main``; skipped with a reason when the variable is unset.

Both sources are pinned to a **JCS digest** (``sha256(RFC 8785(json))``)
recorded in ``VECTOR_PINS``. Formatting-only edits in protocol do not
trip the pin; any content change does, and the failure message tells
the reader which side moved. Refreshing the pin is a deliberate PR in
this repository that also refreshes the hermetic copy.

Invariants exercised (per vector):

1. leaf hashes re-derive through ``compute_leaf_hash`` (JCS four-tuple)
2. tree levels and root re-derive through ``build_merkle_tree``
3. every recorded ``proofs[]`` sibling path equals what
   ``merkle_proof`` emits for that index, and ``verify_merkle_proof``
   returns the recorded ``expected[].verified``
4. vector-2: odd level duplicates the last leaf; the proof for index 2
   carries its own hash as the level-0 sibling on side ``R``
5. vector-3: the untouched proof does **not** verify the tampered leaf
6. every proof document validates against the canonical
   ``wakir-inclusion-proof-v1`` schema from protocol (``$id`` …/0.1.0,
   ``additionalProperties: false``); a stub or a permissive schema in
   protocol is a hard failure, not a skip — armed since protocol
   ``aeba192`` (ADR-0072 W4, canonical schema set)
7. optionally, every proof document validates against the runtime-side
   mirror of that schema when ``WAKIR_RUNTIME_CHECKOUT`` is set
8. every proof document is coherent with the vector's embedded
   ``manifest`` (runtime aggregator form): ``manifest_version`` ==
   ``manifest.version``, ``hour`` == ``manifest.hour_slot``,
   ``merkle_root`` and ``leaf_count`` match
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import rfc8785

from wakir_verify.merkle_proof import (
    build_merkle_tree,
    compute_leaf_hash,
    merkle_proof,
    verify_merkle_proof,
)

# ---------------------------------------------------------------------------
# Locations and pins
# ---------------------------------------------------------------------------

HERMETIC_DIR = Path(__file__).resolve().parent / "fixtures" / "proof-path-vectors"
VECTOR_REL_DIR = Path("tests") / "fixtures" / "proof-path-vectors"
PROTOCOL_SCHEMA_REL = (
    Path("wakir_protocol") / "schemas" / "wakir-inclusion-proof-v1.json"
)
RUNTIME_SCHEMA_REL = Path("wirelang") / "schemas" / "wakir-inclusion-proof-v1.json"

VECTOR_FILES = ("vector-1.json", "vector-2.json", "vector-3.json")

#: Source commit of the hermetic copy in wakir-protocol.
VECTOR_SOURCE_COMMIT = "aeba192e0b60e04cb4e56b7da51faa4e3be14a46"

#: sha256(RFC 8785 JCS(parsed JSON)) per vector file. Content pin —
#: whitespace and key order are irrelevant, every value is not.
VECTOR_PINS: Dict[str, str] = {
    "vector-1.json": "e26fb4a1f82689c5306169066c299a33581a36af5bf1def8562ddd2613a852a6",
    "vector-2.json": "6fba7614ad16b3a0b7dcf64f53ef65949ecc5f275e2edf89acc2b29fe54c9638",
    "vector-3.json": "c8e1b4287543bbb1775e285d8980a8bffb585f56b41c79c0d748749bfd934cb5",
}

VECTOR_SCHEMA = "wakir-proof-path-vector/v1"
PROOF_SCHEMA = "wakir-inclusion-proof/v1"
MANIFEST_VERSION = "wakir-wat-manifest/v1"
CANONICAL_PROOF_SCHEMA_ID = (
    "https://wakir.dev/wirelang/schema/wakir-inclusion-proof-v1/0.1.0"
)
LEAF_KEYS = ("event_id", "time", "payload_hash", "capability_token_hash")

PROTOCOL_ENV = "WAKIR_PROTOCOL_CHECKOUT"
RUNTIME_ENV = "WAKIR_RUNTIME_CHECKOUT"

SOURCES = ("hermetic", "protocol")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _checkout_from_env(var: str, what: str) -> Path:
    raw = os.environ.get(var)
    if not raw:
        pytest.skip(f"{what} checkout not provided; set {var}=<repo-root> (compat workflow does)")
    root = Path(raw)
    if not root.is_dir():
        pytest.fail(f"{var}={raw!r} is not a directory")
    return root


def _vector_dir(source: str) -> Path:
    if source == "hermetic":
        return HERMETIC_DIR
    return _checkout_from_env(PROTOCOL_ENV, "wakir-protocol") / VECTOR_REL_DIR


def _jcs_digest(obj: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _load_vector(source: str, name: str) -> Dict[str, Any]:
    path = _vector_dir(source) / name
    assert path.is_file(), f"{source}: missing {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def _siblings_from_doc(proof: Dict[str, Any]) -> List[Tuple[bytes, str]]:
    return [(bytes.fromhex(s["hash"]), s["side"]) for s in proof["siblings"]]


def _leaf_hashes(vec: Dict[str, Any]) -> List[bytes]:
    out: List[bytes] = []
    for leaf in vec["leaves"]:
        assert tuple(sorted(leaf)) == tuple(sorted(LEAF_KEYS)), leaf.keys()
        out.append(compute_leaf_hash(**{k: leaf[k] for k in LEAF_KEYS}))
    return out


def _load_schema(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(schema: Dict[str, Any]):
    # Plain import, never importorskip: jsonschema is declared in the
    # ".[test]" extra that every pytest lane installs. A guard here would
    # turn "the schema was never validated" into a silent pass.
    import jsonschema

    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _all_proof_docs(vec: Dict[str, Any]) -> List[Dict[str, Any]]:
    docs = list(vec["proofs"])
    if "tampered" in vec:
        docs.append(vec["tampered"]["proof"])
    return docs


# ---------------------------------------------------------------------------
# Pin: content digest on both sources
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", VECTOR_FILES)
def test_vector_matches_pinned_jcs_digest(source: str, name: str) -> None:
    vec = _load_vector(source, name)
    got = _jcs_digest(vec)
    assert got == VECTOR_PINS[name], (
        f"{source}/{name}: JCS digest {got} != pinned {VECTOR_PINS[name]} "
        f"(pin taken from wakir-protocol {VECTOR_SOURCE_COMMIT[:7]}). "
        "Content drift between the protocol vectors and this repository's "
        "hermetic copy. Refresh tests/fixtures/proof-path-vectors/ and "
        "VECTOR_PINS in one PR after confirming the change is intended."
    )


def test_hermetic_and_protocol_copies_are_identical() -> None:
    for name in VECTOR_FILES:
        assert _load_vector("hermetic", name) == _load_vector("protocol", name), name


# ---------------------------------------------------------------------------
# Invariants 1-3: re-derive with wakir_verify.merkle_proof
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", VECTOR_FILES)
def test_leaf_hashes_rederive_with_compute_leaf_hash(source: str, name: str) -> None:
    vec = _load_vector(source, name)
    assert vec["schema"] == VECTOR_SCHEMA
    assert [h.hex() for h in _leaf_hashes(vec)] == vec["leaf_hashes"]


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", VECTOR_FILES)
def test_levels_and_root_rederive_with_build_merkle_tree(source: str, name: str) -> None:
    vec = _load_vector(source, name)
    root, levels = build_merkle_tree(_leaf_hashes(vec))
    assert [[h.hex() for h in lvl] for lvl in levels] == vec["levels"]
    assert root.hex() == vec["merkle_root"]
    assert vec["levels"][-1] == [vec["merkle_root"]]


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", VECTOR_FILES)
def test_recorded_proofs_match_merkle_proof_and_verify(source: str, name: str) -> None:
    vec = _load_vector(source, name)
    leaves = _leaf_hashes(vec)
    root = bytes.fromhex(vec["merkle_root"])
    expected = {e["leaf_index"]: e["verified"] for e in vec["expected"]}
    assert len(vec["proofs"]) == len(leaves) == len(expected)

    for doc in vec["proofs"]:
        idx = doc["leaf_index"]
        assert doc["schema"] == PROOF_SCHEMA
        assert doc["leaf_count"] == len(leaves)
        assert doc["merkle_root"] == vec["merkle_root"]
        assert doc["leaf_hash"] == vec["leaf_hashes"][idx]
        # The verifier's own proof emitter must produce exactly the
        # recorded sibling path, side markers included.
        emitted = [(h.hex(), side) for h, side in merkle_proof(leaves, idx)]
        recorded = [(s["hash"], s["side"]) for s in doc["siblings"]]
        assert emitted == recorded, f"{name} leaf {idx}: sibling path drift"
        assert verify_merkle_proof(leaves[idx], _siblings_from_doc(doc), root) is expected[idx]


# ---------------------------------------------------------------------------
# Invariant 4: duplicate-last rule (vector-2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", SOURCES)
def test_vector_2_duplicate_last_rule(source: str) -> None:
    vec = _load_vector(source, "vector-2.json")
    leaves = _leaf_hashes(vec)
    assert len(leaves) == 3
    lvl0 = vec["levels"][0]
    assert len(lvl0) == 4 and lvl0[2] == lvl0[3] == vec["leaf_hashes"][2]
    doc = vec["proofs"][2]
    assert doc["siblings"][0] == {"hash": vec["leaf_hashes"][2], "side": "R"}
    assert len(doc["siblings"]) == 2
    sib0, side0 = merkle_proof(leaves, 2)[0]
    assert (sib0, side0) == (leaves[2], "R")


def test_vector_1_single_leaf_root_equals_leaf_and_empty_path() -> None:
    vec = _load_vector("hermetic", "vector-1.json")
    leaves = _leaf_hashes(vec)
    assert len(leaves) == 1
    assert vec["merkle_root"] == vec["leaf_hashes"][0]
    assert vec["proofs"][0]["siblings"] == []
    assert merkle_proof(leaves, 0) == []
    assert verify_merkle_proof(leaves[0], [], leaves[0]) is True


# ---------------------------------------------------------------------------
# Invariant 5: tampered leaf (vector-3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", SOURCES)
def test_vector_3_tampered_leaf_does_not_verify(source: str) -> None:
    vec = _load_vector(source, "vector-3.json")
    t = vec["tampered"]
    assert t["expected_verified"] is False
    idx = t["leaf_index"]
    assert t["leaf"] != vec["leaves"][idx]
    tampered_hash = compute_leaf_hash(**{k: t["leaf"][k] for k in LEAF_KEYS})
    assert tampered_hash.hex() == t["leaf_hash"]
    assert t["leaf_hash"] != vec["leaf_hashes"][idx]

    root = bytes.fromhex(vec["merkle_root"])
    siblings = _siblings_from_doc(t["proof"])
    assert verify_merkle_proof(tampered_hash, siblings, root) is False
    # Sanity: the very same proof is intact for the honest leaf.
    assert verify_merkle_proof(bytes.fromhex(vec["leaf_hashes"][idx]), siblings, root) is True


# ---------------------------------------------------------------------------
# Invariant 6: canonical schema from protocol (armed since protocol aeba192)
# ---------------------------------------------------------------------------


def _canonical_schema() -> Dict[str, Any]:
    """Load the canonical proof schema from protocol; refuse stubs."""
    protocol_root = _checkout_from_env(PROTOCOL_ENV, "wakir-protocol")
    schema_path = protocol_root / PROTOCOL_SCHEMA_REL
    assert schema_path.is_file(), f"protocol schema missing at {schema_path}"
    schema = _load_schema(schema_path)
    # The canonical schema is merged (protocol aeba192). A stub marker or
    # a permissive schema reappearing upstream is drift, not a pending arm.
    assert schema.get("x-status") != "stub", "protocol regressed to a stub schema"
    assert "STUB" not in str(schema.get("title", "")), schema.get("title")
    assert schema.get("$id") == CANONICAL_PROOF_SCHEMA_ID, schema.get("$id")
    assert schema.get("additionalProperties") is False, (
        "canonical proof schema must be closed (additionalProperties: false)"
    )
    return schema


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", VECTOR_FILES)
def test_proof_docs_validate_against_protocol_canonical_schema(source: str, name: str) -> None:
    validator = _validator(_canonical_schema())
    vec = _load_vector(source, name)
    docs = _all_proof_docs(vec)
    assert docs, f"{name}: no proof documents"
    for doc in docs:
        validator.validate(doc)


def test_protocol_canonical_schema_rejects_extra_and_missing_fields() -> None:
    """Negative control: the armed schema actually bites."""
    import jsonschema

    validator = _validator(_canonical_schema())
    doc = dict(_load_vector("hermetic", "vector-2.json")["proofs"][2])
    validator.validate(doc)  # honest document passes

    with_extra = {**doc, "x-unexpected": "drift"}
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(with_extra)

    without_required = {k: v for k, v in doc.items() if k != "siblings"}
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(without_required)


# ---------------------------------------------------------------------------
# Invariant 7: runtime-side mirror of the schema (compat workflow, optional)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", VECTOR_FILES)
def test_proof_docs_validate_against_runtime_schema_mirror(name: str) -> None:
    runtime_root = _checkout_from_env(RUNTIME_ENV, "wakir-runtime")
    schema_path = runtime_root / RUNTIME_SCHEMA_REL
    assert schema_path.is_file(), f"runtime schema mirror missing at {schema_path}"
    validator = _validator(_load_schema(schema_path))
    vec = _load_vector("hermetic", name)
    for doc in _all_proof_docs(vec):
        validator.validate(doc)


# ---------------------------------------------------------------------------
# Invariant 8: proofs are coherent with the embedded runtime-form manifest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("name", VECTOR_FILES)
def test_proof_docs_are_coherent_with_embedded_manifest(source: str, name: str) -> None:
    vec = _load_vector(source, name)
    manifest = vec["manifest"]
    assert manifest["version"] == MANIFEST_VERSION
    assert manifest["merkle_root"] == vec["merkle_root"]
    assert manifest["event_count"] == len(vec["leaves"])
    assert [row["leaf_hash"] for row in manifest["leaves"]] == vec["leaf_hashes"]
    assert manifest["tree_levels"] == vec["levels"]
    for doc in _all_proof_docs(vec):
        assert doc["manifest_version"] == manifest["version"]
        assert doc["hour"] == manifest["hour_slot"]
        assert doc["merkle_root"] == manifest["merkle_root"]
        assert doc["leaf_count"] == manifest["event_count"]
