<!--
SPDX-License-Identifier: CC-BY-4.0
SPDX-FileCopyrightText: 2026 Callandor GmbH and contributors
-->

# Quality gates in wakir-verify

## `compat (proof-path against runtime main)` — `.github/workflows/compat.yml`

**What it proves.** The `wakir_verify` library at the PR's commit still
closes the proof path that `wakir-runtime@main` drives end to end with
`make demo-proof`: the runtime-written hour manifest loads through
`wakir_verify.manifest`, its Merkle root re-derives through the
verifier's own tree code, and the runtime-emitted
`wakir-inclusion-proof/v1` document verifies through
`wakir_verify.merkle_proof.verify_merkle_proof`. The report step
`external_verify` must be `ok` — `skipped` is not accepted. In the same
run, the shared proof-path vectors from `wakir-protocol@main` re-derive
through this PR's `compute_leaf_hash`, `build_merkle_tree`,
`merkle_proof` and `verify_merkle_proof`, and the runtime-manifest
loader constraint below is asserted against the manifest the demo just
wrote.

**What it does not prove.** Nothing about Bitcoin anchoring or
OpenTimestamps receipts (the demo runs hermetically, no network). Nothing
about the CLI surface (`wakir-verify` console script) — the gate goes
through the library API on purpose. Nothing about runtime or protocol
PRs: this gate pins verify against their `main`, so it goes red when
*this* repository breaks compatibility, or after an incompatible change
has already landed upstream. Runtime and protocol carry their own gates
for the other direction.

**Error classes it catches.** Signature or semantic changes in
`load_manifest_from_file`, `compute_manifest_consistency`,
`verify_merkle_proof` that the runtime driver depends on; Merkle-rule
drift (leaf tuple, inner hash, duplicate-last, sibling sides) between
verify and the canonical vectors; the `wakir-inclusion-proof/v1` field
set drifting between runtime emitter and verify consumer; a runtime
manifest field rename that the loader would silently swallow (see below);
content drift between protocol's vectors and the hermetic copy in
`tests/fixtures/proof-path-vectors/`.

**Manifest loader constraint (pinned).** The runtime writes `version`
and `hour_slot`; the loader reads `envelope` and `hour`, both optional,
and does not translate. A runtime manifest therefore loads with
`Manifest.envelope == ""` and `Manifest.hour is None`; the runtime values
stay reachable via `Manifest.raw`. `merkle_root`, leaves and consistency
are identical for both shapes. Constant:
`RUNTIME_TO_LOADER_FIELDS = {"version": "envelope", "hour_slot": "hour"}`
in `tests/test_manifest_runtime_compat.py`. Changing either side is
allowed, but must come with an update to that test.

**Arming state.** Fully armed. The report validation runs runtime's
`scripts/ci/validate_demo_proof_report.py <report>
--require-external-verify-ok --expect-commit <runtime@main HEAD>` (on
`runtime@main` since W3); a missing validator is a hard failure, there
is no fallback path any more. Schema validation of the vector proof
documents runs against the canonical
`wakir_protocol/schemas/wakir-inclusion-proof-v1.json` (`$id` …/0.1.0,
`additionalProperties: false`, on `protocol@main` since `aeba192`); a
stub or permissive schema upstream fails the test instead of skipping.
The hermetic vector copy and `VECTOR_PINS` are taken from protocol
`aeba192` (vectors embed a runtime-form `manifest`; vector-2 root
`1f465e05…`). A pin mismatch means protocol moved the vectors again:
refresh copy and pins in one PR after confirming the change.

**Evidence for audit consumers.** A green run is functional test
evidence for the proof path at one commit pair; it is not an audit
trail and makes no statement about governance or mandate compliance.

## Verification semantics — `tests/test_negative_matrix.py`

**What it proves.** That the verifier does not claim more than it
checked. Every case in this file was reproduced against the code as of
`23c3ee8` by the external re-review of 2026-09-14 and produced a
positive or silent result; each is kept as a standing negative control
with the pre-fix output quoted in the module docstring.

The two headline cases:

* **R3.** A file consisting of the OTS magic header plus the *text*
  `BitcoinBlockHeaderAttestation(800000)` — not a timestamp proof —
  reached a 3-of-4 quorum with the `ots` runner reporting failure, and
  reached it identically for an unrelated `anchor_hash`. Three poles
  that never compared the root outvoted the one that could have.
* **R2.** Editing `event_id` and `payload_hash` in a manifest's event
  records while leaving the stored leaf hashes and root untouched kept
  `compute_manifest_consistency()` positive, because it folds the
  stored hashes.

**What it does not prove.** Nothing about Bitcoin: the suite is offline
and the poles are driven through their injection seams. Confirming a
Bitcoin attestation needs a block header, which is a deployment input
(`--block-merkle-root`), not a test fixture.

**The rule the gate encodes.** A positive overall verdict requires a
*mandatory* pole — one that can bind the anchor to a Bitcoin
attestation — to have done so. Supporting poles observe the chain and
contribute evidence; no number of them substitutes for the mandatory
check. `not_checked` is a distinct outcome from both `ok` and `failed`
and must stay distinct: an honestly disabled time proof is acceptable,
a false positive is not.

## Real artefacts — `tests/test_real_receipts.py`

**What it proves.** That the offline receipt walk and the manifest
binding work on the genuine artefacts under
`wakir-runtime/tests/fixtures/wat-*-real*/`, not only on fixtures this
repository wrote for itself. Runs when `WAKIR_RUNTIME_CHECKOUT` points
at a checkout (the compat workflow already sets it); skipped otherwise.

**Two recorded facts, asserted rather than configured away.**

* `wat-tv2-real` (four hours) carries genuine Bitcoin attestations.
  Offline the verdict is `not_checked` with the attested block Merkle
  root printed for manual checking; supplying a block header turns the
  same input into `verified`.
* `wat-tv3-real` and `wat-real-manifest` hold receipts that were never
  upgraded past the calendar stage. They carry **no Bitcoin
  attestation at all**, so no Bitcoin verification is possible from
  them in their stored state. `structural_ok` is the correct outcome
  and is asserted as such.
