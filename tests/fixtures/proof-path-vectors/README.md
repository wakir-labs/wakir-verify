<!--
SPDX-License-Identifier: CC-BY-4.0
SPDX-FileCopyrightText: 2026 Callandor GmbH and contributors
-->

# `tests/fixtures/proof-path-vectors/` — Hermetic copy of the shared proof-path vectors

Canonical home: **wakir-protocol**, `tests/fixtures/proof-path-vectors/`
(`vector-1.json`, `vector-2.json`, `vector-3.json`). The files here are a
byte-for-byte copy taken at protocol commit
`b7de6316d19b3b54125648b2b1a78f171156f5eb` so that `pytest` in this
repository runs without a network and without a second checkout.

`tests/test_proof_path_vectors.py` loads both this copy and, when
`WAKIR_PROTOCOL_CHECKOUT` points at a protocol checkout, the canonical
files. Each file is pinned to a JCS digest (`sha256(RFC 8785(json))`) in
`VECTOR_PINS`; formatting-only changes upstream do not trip the pin,
content changes do.

| File | Scenario | Invariant |
|---|---|---|
| `vector-1.json` | 1 leaf | root == leaf hash, empty sibling path |
| `vector-2.json` | 3 leaves (odd) | duplicate-last: proof for index 2 carries its own hash as level-0 sibling, side `R` |
| `vector-3.json` | 3 leaves + tampered leaf 1 | untouched proof must yield `verified == false` for the tampered leaf |

Hash rules, vector layout and the regeneration note live in the protocol
README next to the canonical files. Do not edit the copies here to make
a red test green: refresh them from protocol together with `VECTOR_PINS`
in one PR, after confirming the upstream change is intended.
