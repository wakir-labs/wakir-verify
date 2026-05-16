<!--
SPDX-FileCopyrightText: 2026 Callandor GmbH and contributors
SPDX-License-Identifier: Apache-2.0
-->

# wakir-verify

**Offline brand-proof verifier for Wakir Audit Trails.**

`wakir-verify` is the open-source verification CLI for audit
trails produced by the Wakir runtime. It checks WAT manifests,
Merkle inclusion proofs and OpenTimestamps-based Bitcoin anchors
**without any dependency on Wakir-controlled software**.

The point: if a third party can reproduce a verdict on a Wakir-
produced audit trail using this CLI alone, the trail's anchoring
claim is independently checkable. That is the contract.

## Why it exists

> *"Trust us because verification is open."*

Wakir's runtime is source-available (BUSL-1.1). The verifier is
not. The verifier is Apache-2.0. Anyone can read it, run it, fork
it, and rebuild it from scratch in a language of their choice. The
Bitcoin-anchor proof Wakir produces stands on its own.

This split is deliberate. See:

- ADR-0034 — repo + license strategy (Tier-1 Apache for the
  verifier).
- ADR-0062 — Phase-2 repo split Cut-1, this repository.

## Install

```bash
pip install wakir-verify
```

Or from source:

```bash
git clone https://github.com/wakir-labs/wakir-verify
cd wakir-verify
pip install -e .
```

Requires Python 3.10 or later.

## Quick start

Given a WAT anchor (the 32-byte Merkle root the runtime emits each
hour) and the OpenTimestamps receipt for that anchor:

```bash
wakir-verify \
    --anchor <hex-root> \
    --ots-proof path/to/root.bin.ots
```

JSON output by default. Pipe to `jq`. For human-readable output:

```bash
wakir-verify --output-format text \
    --anchor <hex-root> \
    --ots-proof path/to/root.bin.ots
```

Exit codes:

- `0` — quorum reached, anchor is attested on Bitcoin.
- `1` — quorum not reached, audit failure.
- `2` — CLI usage error.

## How it works

`wakir-verify` runs the anchor through **four independent
verification poles**:

1. **Pole 1** — Python stdlib OpenTimestamps receipt parser
   (offline; no network).
2. **Pole 2** — Upstream `ots` CLI from the OpenTimestamps
   reference implementation.
3. **Pole 3** — `mempool.space` REST API cross-check.
4. **Pole 4** — `blockstream.info` Esplora REST API cross-check.

Each pole is implemented in a separate module with no
sub-package-internal coupling. The default quorum policy is
**3-of-4**: a single pole disagreeing (because of a transient
HTTP 503 or a rate-limit) does not flip the verdict, but a
fundamental disagreement does. For strict mode, pass `--pols all`.

## Library usage

The CLI is a thin wrapper around two library entry points:

```python
from wakir_verify import (
    verify_wat_anchor,
    QuorumPolicy,
    AnchorVerification,
)

result: AnchorVerification = verify_wat_anchor(
    anchor_hash="<64-char-hex>",
    ots_proof_path="path/to/proof.ots",
    quorum_policy=QuorumPolicy.THREE_OF_FOUR,
)

if result.quorum.passed:
    ...
```

Manifest helpers:

```python
from wakir_verify.manifest import load_manifest_from_file
from wakir_verify.merkle_proof import (
    merkle_proof,
    verify_merkle_proof,
)

manifest = load_manifest_from_file("manifest.json")
leaves = manifest.leaf_hashes
proof = merkle_proof(leaves, manifest.find_leaf("evt-123"))
assert verify_merkle_proof(
    leaf=leaves[manifest.find_leaf("evt-123")],
    proof=proof,
    root=manifest.merkle_root,
)
```

## Sandbox-safe testing

Every HTTP-shaped pole accepts a per-call ``transport`` argument
and the OTS-CLI pole accepts a per-call ``ots_runner``. The test
suite injects fakes; no live network call happens under `pytest`.

```bash
pytest tests/
```

## Repository topology

`wakir-verify` is the open-source verifier in a broader four-repo
Wakir topology:

| Repo | License | Purpose |
|---|---|---|
| `wakir-labs/wakir-verify` | Apache-2.0 | offline brand-proof verifier (this repo) |
| `wakir-labs/wakir-protocol` | Apache-2.0 + CC-BY-4.0 | protocol specs (planned, Cut-2) |
| `wakir-labs/wakir-runtime` | BUSL-1.1 + Apache-2.0 mix | runtime, source-available |
| `wakir-labs/infra` | Apache-2.0 | generic reference patterns |

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

This sub-package was migrated from `wakir-runtime/wat/anchor/
external_verifier/` plus the Merkle-Read-Half of `wat/merkle/` in
ADR-0062 Cut-1. The migration classification is documented in
`wakir-runtime/docs/decisions/cut1-verifier-substance-classification.md`.
