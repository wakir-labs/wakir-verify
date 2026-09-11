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

**Arming schedule.** The report validation uses runtime's
`scripts/ci/validate_demo_proof_report.py --require-external-verify-ok`
once it exists on `runtime@main`; until then the workflow runs a marked
fallback check (stdlib only, same assertions, logged as `FALLBACK`).
Schema validation of the vector proof documents against
`wakir_protocol/schemas/wakir-inclusion-proof-v1.json` skips with a
reason while protocol ships the stub (`x-status: stub`) and arms
automatically once the canonical schema is merged.

**Evidence for audit consumers.** A green run is functional test
evidence for the proof path at one commit pair; it is not an audit
trail and makes no statement about governance or mandate compliance.
