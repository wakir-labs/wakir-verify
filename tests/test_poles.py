# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Per-pole tests for the 4-pole external verifier.

Covers each pole's local contract:

* ``pole_python_stdlib`` — structural-only and injected-reader paths.
* ``pole_ots_cli`` — output-parse, returncode handling, missing-binary
  unavailability, injection seam.
* HTTP poles — status-code handling, malformed body, witness-capture
  mode, base-url override.
"""

from __future__ import annotations

import pytest

from wakir_verify import poles as p
from wakir_verify.poles import HttpResponse

from tests.fixtures import (
    BLOCK_HASH_948183,
    RECEIPT_948183_BYTES,
    RECEIPT_PENDING_BYTES,
    make_http_transport,
    make_ots_runner,
    make_proof_reader,
)


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"


# ---------------------------------------------------------------------------
# Pole 1 — python-stdlib structural
# ---------------------------------------------------------------------------


def test_pole_python_stdlib_structural_happy_path(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
    )
    assert r.ok is True
    assert r.verdict == "verified"
    assert 948183 in r.witness["heights"]


def test_pole_python_stdlib_structural_no_height_in_pending_receipt(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_PENDING_BYTES)
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert "no BitcoinBlockHeaderAttestation" in r.note


def test_pole_python_stdlib_missing_file_is_unavailable(tmp_path):
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(tmp_path / "does-not-exist.ots"),
    )
    assert r.ok is False
    assert r.verdict == "unavailable"


def test_pole_python_stdlib_missing_magic_is_failed(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(b"this is not an OTS receipt at all")
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert "magic header" in r.note


def test_pole_python_stdlib_injected_proof_reader_accepts_correct_root(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    reader = make_proof_reader(
        merkle_root_hex=ANCHOR_HEX,
        heights=[948183],
    )
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        proof_reader=reader,
    )
    assert r.ok is True
    assert r.witness["reader"] == "injected"


def test_pole_python_stdlib_injected_proof_reader_rejects_wrong_root(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    # Reader reports a different root than the caller asserts
    reader = make_proof_reader(
        merkle_root_hex="ab" * 32,
        heights=[948183],
    )
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        proof_reader=reader,
    )
    assert r.ok is False
    assert r.verdict == "failed"


def test_pole_python_stdlib_injected_proof_reader_handles_raised(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)

    def _boom(blob):
        raise RuntimeError("reader boom")

    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        proof_reader=_boom,
    )
    assert r.ok is False
    assert "reader boom" in r.note


# ---------------------------------------------------------------------------
# Pole 2 — ots CLI
# ---------------------------------------------------------------------------


def test_pole_ots_cli_happy_path(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    runner = make_ots_runner(
        stdout="BitcoinBlockHeaderAttestation(948183)\n",
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        ots_runner=runner,
    )
    assert r.ok is True
    assert 948183 in r.witness["heights"]


def test_pole_ots_cli_nonzero_returncode_is_failed(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    runner = make_ots_runner(
        stdout="error: malformed receipt", returncode=1
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        ots_runner=runner,
    )
    assert r.ok is False
    assert "returncode=1" in r.note


def test_pole_ots_cli_height_mismatch(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    runner = make_ots_runner(
        stdout="BitcoinBlockHeaderAttestation(948183)\n",
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=999_999,
        ots_runner=runner,
    )
    assert r.ok is False
    assert "expected height" in r.note


def test_pole_ots_cli_missing_binary_is_unavailable(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    # Don't inject a runner -> real shutil.which path. Use an
    # unambiguously-absent binary name so the test does not depend
    # on host PATH.
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        ots_bin="ots-binary-that-definitely-does-not-exist-12345",
    )
    assert r.ok is False
    assert r.verdict == "unavailable"


def test_pole_ots_cli_missing_proof_file_is_unavailable(tmp_path):
    runner = make_ots_runner(stdout="")
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(tmp_path / "nope.ots"),
        ots_runner=runner,
    )
    assert r.ok is False
    assert r.verdict == "unavailable"


# ---------------------------------------------------------------------------
# Pole 3 / Pole 4 — Esplora REST
# ---------------------------------------------------------------------------


def test_pole_mempool_space_happy_path(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    transport = make_http_transport(
        block_hash_by_height={948183: BLOCK_HASH_948183},
    )
    r = p.pole_mempool_space_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        expected_block_hash=BLOCK_HASH_948183,
        transport=transport,
    )
    assert r.ok is True
    assert r.witness["observed_block_hash"] == BLOCK_HASH_948183


def test_pole_esplora_blockstream_witness_capture_mode(tmp_path):
    """No expected_block_hash -> reports observed hash, ok=True."""
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    transport = make_http_transport(
        block_hash_by_height={948183: BLOCK_HASH_948183},
    )
    r = p.pole_esplora_blockstream_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        expected_block_hash=None,
        transport=transport,
    )
    assert r.ok is True
    assert r.witness["mode"] == "witness-capture"
    assert r.witness["observed_block_hash"] == BLOCK_HASH_948183


def test_pole_http_503_is_unavailable(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    transport = make_http_transport(
        block_hash_by_height={},
        failure_status_for_heights={948183: 503},
    )
    r = p.pole_mempool_space_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        transport=transport,
    )
    assert r.ok is False
    assert r.verdict == "unavailable"
    assert r.witness["status"] == 503


def test_pole_http_malformed_body(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)

    def transport(url, timeout):
        return HttpResponse(status=200, body="not-a-block-hash")

    r = p.pole_mempool_space_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        expected_block_hash=BLOCK_HASH_948183,
        transport=transport,
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert "malformed block hash" in r.note


def test_pole_http_block_hash_mismatch(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    wrong_hash = "a" * 64
    transport = make_http_transport(
        block_hash_by_height={948183: wrong_hash},
    )
    r = p.pole_esplora_blockstream_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        expected_block_hash=BLOCK_HASH_948183,
        transport=transport,
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert "mismatch" in r.note


def test_pole_http_negative_height_rejected(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    transport = make_http_transport(block_hash_by_height={})
    r = p.pole_mempool_space_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=-1,
        transport=transport,
    )
    assert r.ok is False
    assert r.verdict == "failed"


def test_pole_http_url_shape(tmp_path):
    """Pole hits ``<base>/block-height/<H>`` exactly."""
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    captured: list[str] = []

    def transport(url, timeout):
        captured.append(url)
        return HttpResponse(status=200, body=BLOCK_HASH_948183 + "\n")

    p.pole_mempool_space_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        expected_block_hash=BLOCK_HASH_948183,
        transport=transport,
        base_url="https://mempool.space/api",
    )
    assert captured == ["https://mempool.space/api/block-height/948183"]
