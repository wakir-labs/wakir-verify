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

## `bitcoinlib-drift` — `.github/workflows/bitcoinlib-drift.yml`

**What it proves.** That `wakir_verify` stays stable across the
`python-bitcoinlib` lineage an external auditor is likely to install.
The verifier ships a zero-PyPI-surface structural pole and never
imports `bitcoin` itself, but the pole accepts an injected
`proof_reader`, and the Position-Paper §L4-References annex names
`python-bitcoinlib` as the canonical stdlib-OTS-parser axis. If a
future release flips block-hash byte order in `b2lx`, changes hex
casing, or alters OP_RETURN script canonicalisation, an auditor's
independent check would silently disagree with ours months later.
The matrix pins `0.11.2` / `0.12.1` / `0.12.2` — no floating tag, so a
red lane always names a cause.

**Why it exists here.** `tests/test_python_bitcoinlib_drift.py` was in
this repository from the start, but nothing ever installed
`python-bitcoinlib`, so `pytest.importorskip` skipped the module on
every single run. The matrix that gave it teeth lived in
`wakir-runtime` and drove the duplicated verifier copy that ADR-0074
removes. The workflow was absorbed here with the copy's deletion.

**Not a required check, on purpose.** It probes a third-party library
lineage we do not control; an upstream yank must not block a PR. The
required proof-path contexts stay `ci` and
`compat (proof-path against runtime main)`. What the lane *does*
hard-fail on is a skipped probe: once the pinned install succeeds, the
job asserts from the JUnit report that the module ran and skipped
nothing — the failure mode that let this probe sit dormant.

## `pytest (py3.13)` — lane inventory (`tests/test_required_lane_inventory.py`)

**What it proves.** That the required lane *found* every test module —
not just that the assertions which ran, passed. A green tick is evidence
about executed assertions only; a module that never collects is
indistinguishable from one that collected and passed.

**Why it is a test and not a workflow step.** It runs inside the
existing required context, so it needs no new status check and no
branch-protection change. (A new required context has to be registered
with its exact job display name; getting that wrong leaves PRs pending
forever.) The check shells out to `pytest tests/ --collect-only` and
reads the result.

**The three ways a module leaves a green lane**, and what closes each:

| Failure mode | Closed by |
|---|---|
| collection error swallowed (e.g. `--continue-on-collection-errors` added to `addopts`) | `test_collect_only_reports_no_errors` — pins both the `0` exit code and the absence of `ERROR` lines |
| module-level `pytest.importorskip` on something the lane installs | `test_import_guards_are_on_non_lane_imports_only` |
| `importorskip` inside a helper or fixture — removes individual tests, quieter than the above | same test; the scan walks the whole AST, not only module-level statements |

**The recorded occasion.** `tests/test_python_bitcoinlib_drift.py` hung
on `importorskip` from the repo split until ADR-0074 and no lane
installed the library, so the one probe that compares against an
independent third-party implementation was skipped on every run. It was
found by hand, months later. Two further guards — `hypothesis` at module
level in `test_property_hypothesis.py`, `jsonschema` twice inside a
helper in `test_proof_path_vectors.py` — named distributions that
**every** pytest lane here installs via `.[test]`; they could only ever
have hidden tests, never adapted to a leaner lane. All three were
replaced by plain imports.

**The one guard that stays**, with its reason recorded in
`ALLOWED_IMPORT_GUARDS`: `bitcoin` (python-bitcoinlib) is deliberately
not a dependency of this package and is installed only by the
`bitcoinlib-drift` matrix, which itself hard-fails on a skipped probe.
`test_guarded_module_contributes_when_its_import_is_available` keeps that
allowance conditional: wherever `bitcoin` imports, the module must
collect.

**Premise check.** `test_every_lane_that_runs_pytest_installs_the_test_extra`
asserts that every workflow running pytest installs `".[test]"`. That
premise is what makes the plain `hypothesis`/`jsonschema` imports correct;
a future lane that trims the extra fails here rather than at a confusing
import error.
