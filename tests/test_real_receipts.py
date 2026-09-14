# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Positive control: the real receipts and manifests in the ecosystem.

A verifier that only ever meets its own fixtures is checking its own
imagination. These tests run the offline pole and the manifest binding
against the genuine artefacts under ``tests/fixtures/wat-*-real*/`` in
a ``wakir-runtime`` checkout: manifests produced by the hourly
aggregator, 32-byte roots, and ``.ots`` receipts returned by the public
OpenTimestamps calendars.

Skipped when no checkout is pointed at by ``WAKIR_RUNTIME_CHECKOUT``
(the variable the compat workflow already sets). Nothing here touches
the network: the receipts are read from disk and walked offline.

What the real artefacts establish, and what they do not
-------------------------------------------------------

* Every receipt parses, and every receipt's file digest equals SHA-256
  of its ``root.bin`` — the binding the pre-fix code never checked.
* ``wat-tv2-real`` carries genuine Bitcoin attestations. Offline, the
  verifier can produce the attested block Merkle root but cannot
  confirm it without a block header, so the honest verdict is
  ``not_checked`` with the claim printed. Supply
  ``--block-merkle-root`` from a node and the same input verifies;
  that path is exercised here with the claim itself, which proves the
  comparison runs and not that the chain agrees.
* ``wat-tv3-real`` and ``wat-real-manifest`` carry *only* pending
  calendar attestations. They were never upgraded, so there is no
  Bitcoin claim in them at all. ``structural_ok`` is the correct
  result and it is asserted here rather than configured away.

That last point is a finding, not a defect of this change: two of the
four checked-in "real" anchor fixtures cannot support a Bitcoin
verification in the state they are stored in.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from wakir_verify.binding import (
    check_event_binding,
    check_hashlist_consistency,
)
from wakir_verify.claims import STATUS_OK
from wakir_verify.manifest import load_manifest_from_file
from wakir_verify.ots_proof import match_anchor_binding, parse_ots_receipt
from wakir_verify.poles import pole_python_stdlib_verify

RUNTIME_CHECKOUT_ENV = "WAKIR_RUNTIME_CHECKOUT"

#: Fixture directories holding a real ``manifest.json`` + ``root.bin``
#: + ``root.bin.ots`` triple, relative to a runtime checkout.
_ANCHORED = (
    "tests/fixtures/wat-tv2-real/2026-05-27T00",
    "tests/fixtures/wat-tv2-real/2026-05-27T01",
    "tests/fixtures/wat-tv2-real/2026-05-27T02",
    "tests/fixtures/wat-tv2-real/2026-05-27T03",
)
_PENDING_ONLY = (
    "tests/fixtures/wat-tv3-real/2026-05-26T17",
    "tests/fixtures/wat-real-manifest",
)


def _runtime_root() -> Path:
    raw = os.environ.get(RUNTIME_CHECKOUT_ENV)
    if not raw:
        pytest.skip(f"{RUNTIME_CHECKOUT_ENV} not set")
    root = Path(raw)
    if not root.is_dir():
        pytest.skip(f"{RUNTIME_CHECKOUT_ENV}={raw} is not a directory")
    return root


def _case(rel: str) -> tuple[Path, dict]:
    directory = _runtime_root() / rel
    if not directory.is_dir():
        pytest.skip(f"fixture {rel} not present in this runtime checkout")
    return directory, json.loads((directory / "manifest.json").read_text())


@pytest.mark.parametrize("rel", _ANCHORED + _PENDING_ONLY)
def test_real_receipt_parses_and_binds_to_its_root(rel):
    directory, manifest = _case(rel)
    blob = (directory / "root.bin.ots").read_bytes()
    root_bytes = (directory / "root.bin").read_bytes()

    receipt = parse_ots_receipt(blob)
    assert receipt.file_hash_op == "sha256"
    assert receipt.file_digest_hex == hashlib.sha256(root_bytes).hexdigest()
    assert root_bytes.hex() == manifest["merkle_root"]

    binding = match_anchor_binding(manifest["merkle_root"], receipt)
    assert binding.bound is True
    assert binding.mode == "sha256(root-bytes)"


@pytest.mark.parametrize("rel", _ANCHORED + _PENDING_ONLY)
def test_real_manifest_binds_its_events(rel):
    directory, _ = _case(rel)
    manifest = load_manifest_from_file(directory / "manifest.json")

    assert check_hashlist_consistency(manifest).status == STATUS_OK
    # The real manifests carry all four B1 fields per leaf, so the
    # event binding is checkable without any extra input.
    assert check_event_binding(manifest).status == STATUS_OK


@pytest.mark.parametrize("rel", _ANCHORED)
def test_anchored_receipt_is_not_checked_offline_then_verifies(rel):
    directory, manifest = _case(rel)
    anchor = manifest["merkle_root"]
    proof_path = str(directory / "root.bin.ots")

    offline = pole_python_stdlib_verify(
        anchor_hash=anchor, ots_proof_path=proof_path
    )
    assert offline.verdict == "not_checked"
    assert offline.witness["binding"]["bound"] is True
    claims = offline.witness["bitcoin_claims"]
    assert claims, "tv2 receipts are expected to carry Bitcoin attestations"

    # Feed the receipt's own claim back as the block header. This
    # proves the comparison path runs end to end on a real receipt; it
    # does not prove Bitcoin agrees, and must not be read as if it did.
    supplied = {c["height"]: c["claimed_block_merkle_root"] for c in claims}
    confirmed = pole_python_stdlib_verify(
        anchor_hash=anchor,
        ots_proof_path=proof_path,
        block_merkle_roots=supplied,
    )
    assert confirmed.ok is True
    assert confirmed.verdict == "verified"

    # And a header that disagrees is rejected rather than shrugged off.
    contradicted = pole_python_stdlib_verify(
        anchor_hash=anchor,
        ots_proof_path=proof_path,
        block_merkle_roots={h: "0" * 64 for h in supplied},
    )
    assert contradicted.verdict == "failed"


@pytest.mark.parametrize("rel", _PENDING_ONLY)
def test_pending_only_receipt_reports_structural_ok(rel):
    """Documented outcome, not a configured-away one.

    These two fixtures hold receipts that were never upgraded past the
    calendar stage. No Bitcoin attestation exists in them, so no
    Bitcoin verification is possible from them, and the verifier says
    exactly that.
    """
    directory, manifest = _case(rel)
    result = pole_python_stdlib_verify(
        anchor_hash=manifest["merkle_root"],
        ots_proof_path=str(directory / "root.bin.ots"),
    )
    assert result.verdict == "structural_ok"
    assert result.ok is False
    assert "no Bitcoin attestation" in result.note
    assert parse_ots_receipt(
        (directory / "root.bin.ots").read_bytes()
    ).pending_attestations


@pytest.mark.parametrize("rel", _ANCHORED)
def test_real_receipt_does_not_vouch_for_another_root(rel):
    directory, _ = _case(rel)
    result = pole_python_stdlib_verify(
        anchor_hash="c" * 64,
        ots_proof_path=str(directory / "root.bin.ots"),
    )
    assert result.verdict == "failed"
    assert "does not attest this root" in result.note
