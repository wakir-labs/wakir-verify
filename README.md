<!--
SPDX-FileCopyrightText: 2026 Callandor GmbH and contributors
SPDX-License-Identifier: Apache-2.0
-->

# wakir-verify

**Wakir Audit Trail Verifier — offline brand-proof for cryptographic
audit trails.**

`wakir-verify` is a stand-alone command-line tool that verifies audit
trails produced by the [Wakir runtime](https://github.com/wakir-labs/wakir-runtime).
It validates WAT manifests, checks Merkle inclusion proofs, and
confirms OpenTimestamps-based Bitcoin anchors — all without any
runtime dependency on Wakir-controlled software, and without a
network connection for the offline poles.

The point: if a third party can reproduce a verdict on a Wakir-
produced audit trail using this CLI alone, the trail's anchoring
claim is independently checkable. That is the contract.

## What it is

- An **open-source, Apache-2.0 licensed** CLI for verifying Wakir
  audit trails: manifests, Merkle inclusion proofs, and OpenTimestamps
  Bitcoin anchors.
- A **stand-alone** package. It pulls no `wakir-runtime` dependency
  at install or run time, and has no hidden coupling back to Wakir
  infrastructure.
- A **library** that exposes the same verification primitives the
  CLI uses (`verify_wat_anchor`, `merkle_proof`, `load_manifest_from_file`),
  so third parties can embed the verifier in their own tooling.

## What it is not

- Not an audit-trail **generator**. The runtime emits trails; this
  tool only reads them. See `wakir-labs/wakir-runtime`.
- Not a **hosted service**. There is no API endpoint, no SaaS, no
  account. The CLI runs on your machine against your files.
- Not a **Verification-as-a-Service**. If you need attested
  verification reports, you run the CLI yourself and keep the
  output. Wakir does not see your trails.

## Why it exists

> *"Trust us because verification is open."*

The Wakir runtime is source-available under BUSL-1.1. The verifier
is not — it is Apache-2.0. Anyone can read it, run it, fork it, and
rebuild it from scratch in a language of their choice. The Bitcoin-
anchor proof Wakir produces has to stand on its own; this CLI is the
reference contract for what "stands on its own" means in practice.

The split is deliberate. See:

- [ADR-0034](https://github.com/wakir-labs/) — repo + license
  strategy (Tier-1 Apache-2.0 for the verifier).
- [ADR-0062](https://github.com/wakir-labs/) — Phase-2 repo split,
  Cut-1, this repository.

## Install

For now, install from source:

```bash
git clone https://github.com/wakir-labs/wakir-verify
cd wakir-verify
pip install -e .
```

Requires Python 3.10 or later.

A PyPI release (`pip install wakir-verify`) is planned with the
`v0.1.0` tag once the Cut-1 acceptance gates close. Until then the
source-install path above is the supported route.

## Quick start

Given a WAT anchor (the 32-byte Merkle root the runtime emits each
hour) and the OpenTimestamps receipt for that anchor:

```bash
wakir-verify --help
```

A minimal round-trip:

```bash
# 1. Read the anchor your runtime committed.
ANCHOR=$(jq -r .merkle_root manifest.json)

# 2. Run the verifier against the matching .ots receipt.
wakir-verify \
    --anchor "$ANCHOR" \
    --ots-proof anchor.bin.ots

# 3. Exit code is the verdict.
#    0 = quorum reached, anchor attested on Bitcoin.
#    1 = quorum not reached, audit failure.
#    2 = CLI usage error.
```

JSON output by default. Pipe to `jq` for scripting. For human-
readable output:

```bash
wakir-verify --output-format text \
    --anchor "$ANCHOR" \
    --ots-proof anchor.bin.ots
```

## Architecture

`wakir-verify` is built from three substrate layers plus a stand-
alone Bitcoin block-header verifier:

1. **Manifest layer** (`wakir_verify.manifest`) — parses a WAT
   manifest, validates schema, and exposes leaf hashes plus the
   committed Merkle root.
2. **Merkle layer** (`wakir_verify.merkle_proof`) — recomputes an
   inclusion proof from leaves, verifies a proof against a root,
   independent of how the manifest was produced.
3. **OpenTimestamps layer** (`wakir_verify.ots_verify`,
   `wakir_verify.aggregator`) — parses the `.ots` receipt and walks
   it to a Bitcoin block-header attestation.
4. **Bitcoin-header standalone verify** (`wakir_verify.bitcoin_header`) —
   given a height, hash, and header bytes, checks the proof-of-work
   on the header itself, without trusting any third-party API to
   speak truth about Bitcoin.

The Bitcoin-anchor pole is cross-checked through **four independent
verification poles** to defeat single-source bias:

1. **Pole 1** — Python stdlib OpenTimestamps receipt parser
   (offline, no network).
2. **Pole 2** — Upstream `ots` CLI from the OpenTimestamps reference
   implementation.
3. **Pole 3** — `mempool.space` REST API cross-check.
4. **Pole 4** — `blockstream.info` Esplora REST API cross-check.

Default quorum is **3-of-4**: a single pole failing because of a
transient HTTP 503 or rate limit does not flip the verdict, but a
fundamental disagreement does. Pass `--pols all` for strict mode.

## Substance anchors

This is not a marketing claim. The contract is exercised in tests
that are part of the repository:

- **`tests/test_witness_captures.py`** — fixture-replay against the
  live OpenTimestamps receipt for **Bitcoin block 948183**, captured
  2026-05-13. The capture file under
  `tests/fixtures/witness_captures/2026-05-13-block-948183.json`
  pins the 4-pole aggregator contract: replay the capture, the
  verdict must match.
- **`tests/test_property_hypothesis.py`** — Hypothesis property-
  based suite. Generates parser-input variants, anchor-verification
  shapes, and pole-witness combinations, and asserts the aggregator
  produces the same verdict on equivalent inputs. The block-948183
  witness is one of the canonical seeds.
- **`tests/test_poles.py`**, **`tests/test_aggregator.py`**,
  **`tests/test_multi_pol_determinismus.py`** — per-pole and
  aggregator-level determinism tests.

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

Manifest and Merkle helpers:

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

Every HTTP-shaped pole takes a per-call `transport` argument, and
the OTS-CLI pole takes a per-call `ots_runner`. The test suite
injects fakes; no live network call happens under `pytest`.

```bash
pip install -e .[test]
pytest tests/
```

## Repository topology

`wakir-verify` is one of four repositories in the Wakir Labs
ecosystem:

| Repo | License | Purpose |
|---|---|---|
| `wakir-labs/wakir-verify` | Apache-2.0 | offline brand-proof verifier (this repo) |
| `wakir-labs/wakir-protocol` | Apache-2.0 + CC-BY-4.0 | protocol specs (planned, Cut-2) |
| `wakir-labs/wakir-runtime` | BUSL-1.1 + Apache-2.0 mix | runtime, source-available |
| `wakir-labs/infra` | Apache-2.0 | generic reference patterns |

The verifier is open so that adopters can decide for themselves
whether the runtime's attestation claims are trustworthy.

## License

Apache-2.0. Clean. See `LICENSE` and `NOTICE`.

This sub-package was migrated from `wakir-runtime/wat/anchor/external_verifier/`
plus the read-half of `wat/merkle/` in ADR-0062 Cut-1. The migration
classification is documented at
`wakir-runtime/docs/decisions/cut1-verifier-substance-classification.md`.

— Wakir Labs Editorial
