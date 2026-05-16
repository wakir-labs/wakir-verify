# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""MVP tests for the merkle-proof read-half."""

from __future__ import annotations

import hashlib

import pytest

from wakir_verify.merkle_proof import (
    build_merkle_tree,
    compute_inner_hash,
    leaf_hash,
    merkle_proof,
    root_hash,
    verify_merkle_proof,
)


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def test_root_hash_single_leaf_equals_leaf():
    h = leaf_hash(b'{"x":1}')
    assert root_hash([h]) == h


def test_root_hash_two_leaves():
    a = leaf_hash(b'{"i":0}')
    b = leaf_hash(b'{"i":1}')
    expected = compute_inner_hash(a, b)
    assert root_hash([a, b]) == expected


def test_root_hash_odd_leaves_duplicates_last_bitcoin_pattern():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(3)]
    # Bitcoin convention: duplicate last node on odd level
    l01 = compute_inner_hash(leaves[0], leaves[1])
    l23 = compute_inner_hash(leaves[2], leaves[2])
    expected = compute_inner_hash(l01, l23)
    assert root_hash(leaves) == expected


def test_root_hash_empty_raises():
    with pytest.raises(ValueError):
        root_hash([])


def test_build_merkle_tree_returns_levels():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(4)]
    root, levels = build_merkle_tree(leaves)
    assert len(levels) == 3  # 4 leaves -> 4, 2, 1
    assert levels[0] == leaves
    assert levels[-1] == [root]


def test_merkle_proof_round_trip_4_leaves():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(4)]
    root, _ = build_merkle_tree(leaves)
    for idx in range(4):
        proof = merkle_proof(leaves, idx)
        assert verify_merkle_proof(leaves[idx], proof, root)


def test_merkle_proof_round_trip_3_leaves_bitcoin_pad():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(3)]
    root, _ = build_merkle_tree(leaves)
    for idx in range(3):
        proof = merkle_proof(leaves, idx)
        assert verify_merkle_proof(leaves[idx], proof, root)


def test_merkle_proof_round_trip_7_leaves():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(7)]
    root, _ = build_merkle_tree(leaves)
    for idx in range(7):
        proof = merkle_proof(leaves, idx)
        assert verify_merkle_proof(leaves[idx], proof, root)


def test_verify_merkle_proof_rejects_tampered_leaf():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(4)]
    root, _ = build_merkle_tree(leaves)
    proof = merkle_proof(leaves, 2)
    tampered = bytes(b ^ 0xFF for b in leaves[2])
    assert not verify_merkle_proof(tampered, proof, root)


def test_verify_merkle_proof_rejects_tampered_root():
    leaves = [leaf_hash(f'{{"i":{i}}}'.encode()) for i in range(4)]
    root, _ = build_merkle_tree(leaves)
    bad_root = bytes(b ^ 0xFF for b in root)
    proof = merkle_proof(leaves, 1)
    assert not verify_merkle_proof(leaves[1], proof, bad_root)
