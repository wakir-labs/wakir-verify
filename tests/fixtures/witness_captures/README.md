<!--
SPDX-License-Identifier: CC-BY-4.0
SPDX-FileCopyrightText: 2026 Callandor GmbH and contributors
-->

# `tests/wat/external_verifier/witness_captures/` — Saved Witness Fixtures

This directory holds the brand-proof witness-capture JSON artefacts
the Tag-2 `wat-verify --capture-witnesses` command emits. Each file
records the canonical Bitcoin block hash observed by mempool.space
and blockstream.info at the moment of capture, pinned next to the
WAT anchor hash and the block height.

The fixtures are checked into the runtime so the test suite under
`test_witness_captures.py` can replay them hermetically. The
external-verifier contract is "any third-party auditor can rerun the
verifier with the saved witness JSON and the .ots receipt to
reproduce the verdict without operating any Wakir-controlled
software" — these files are the substance of that contract.

## File catalogue

| File | Mode | Captured against | Replay verdict |
|------|------|------------------|----------------|
| `2026-05-13-block-948183.json` | live | `mempool.space/api`, `blockstream.info/api`, block 948183, anchor `d16216b9…1894` | verified under 3-of-4 and ALL |
| `2026-05-13-block-948183-tampered-mock.json` | mock-divergence | hand-mutated copy of the live capture (single-nibble flip in pole_mempool_space) | passes 3-of-4 with visible divergence; fails ALL |

## Mock-file convention

Synthetic / hand-edited captures are flagged by a top-level
`_comment_mock_marker` key. Auditors and CI grep for that exact key
to distinguish authoritative live captures from synthetic divergence
tests; no live capture file may carry the marker.

## Replay recipe

```sh
# offline replay: takes a saved witness file and a .ots receipt,
# pins the expected_block_hash from the saved canonical hash,
# runs the 4-pole quorum.
python -m wat.anchor.external_verifier.cli \
    --anchor    "$(jq -r .anchor_hash       <witness-file>.json)" \
    --ots-proof <receipt-path> \
    --expected-block-height $(jq -r .block_height  <witness-file>.json) \
    --expected-block-hash   $(jq -r '.pole_witnesses.pole_esplora_blockstream.witness.observed_block_hash' <witness-file>.json) \
    --output-format text \
    --pols all
```

When the live Esplora endpoints have not been disturbed since the
capture, the replay yields `VERIFIED`. When the chain has reorged or
the saved file has been tampered with, the HTTP poles flip to
`failed` and the verdict is `AUDIT FAILURE` — this is the contract.

## Sandbox-host separation

Saved witness captures move freely between the sandbox (CI,
hermetic tests) and the operator host (live capture). The
sandbox-host separation contract (Memory `feedback_sandbox_host_trennung.md`)
is preserved: live capture is an operator-host action because it
requires outbound HTTP; replay is a sandbox-safe action because it
runs entirely against the saved JSON plus the injection seams the
poles expose.
