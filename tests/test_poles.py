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
    attested_message,
    block_merkle_root_display,
    build_ots_receipt,
    make_http_transport,
    make_ots_runner,
    make_proof_reader,
    receipt_file_digest,
)


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"

#: One append + one sha256 before the attestation, so the attested
#: message is not simply the file digest — as on a real calendar path.
_BRANCH_OPS = [("append", b"\x11" * 16), ("sha256",)]


def _receipt_bytes(anchor_hex: str = ANCHOR_HEX, height: int = 948183) -> bytes:
    return build_ots_receipt(
        file_digest=receipt_file_digest(anchor_hex),
        branches=[{"ops": _BRANCH_OPS, "attestation": ("bitcoin", height)}],
    )


def _claimed_root(anchor_hex: str = ANCHOR_HEX) -> str:
    return block_merkle_root_display(
        attested_message(receipt_file_digest(anchor_hex), _BRANCH_OPS)
    )


# ---------------------------------------------------------------------------
# Pole 1 — python-stdlib structural
# ---------------------------------------------------------------------------


def test_pole_python_stdlib_bound_receipt_without_block_header_is_not_checked(
    tmp_path,
):
    """A bound receipt alone is not a Bitcoin verification.

    Expectation changed with the R3 fix. This test used to feed the
    magic header plus the text ``BitcoinBlockHeaderAttestation(948183)``
    and assert ``verified`` — a positive verdict about a root the pole
    never compared. The receipt is now real, the root binding is
    checked, and the Bitcoin side stays ``not_checked`` until a block
    header is supplied.
    """
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
    )
    assert r.ok is False
    assert r.verdict == "not_checked"
    assert r.role == "mandatory"
    assert r.witness["binding"]["bound"] is True
    assert 948183 in r.witness["heights"]
    assert "no block header was supplied" in r.note


def test_pole_python_stdlib_verifies_against_supplied_block_header(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        block_merkle_roots={948183: _claimed_root()},
    )
    assert r.ok is True
    assert r.verdict == "verified"
    assert r.is_root_bound is True


def test_pole_python_stdlib_rejects_contradicting_block_header(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
        block_merkle_roots={948183: "0" * 64},
    )
    assert r.ok is False
    assert r.verdict == "failed"


def test_pole_python_stdlib_pending_only_receipt_is_structural_ok(tmp_path):
    """A pending receipt is un-upgraded, not wrong.

    Expectation changed with the R3 fix: ``failed`` conflated "this
    timestamp has not reached Bitcoin yet" with "this timestamp is
    bad". The receipt is bound to the root and honest about carrying
    only calendar attestations, so the verdict is ``structural_ok``
    and the overall run cannot turn positive on it.
    """
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(
        build_ots_receipt(
            file_digest=receipt_file_digest(ANCHOR_HEX),
            branches=[
                {
                    "ops": [],
                    "attestation": ("pending", "https://alice.calendar.test"),
                }
            ],
        )
    )
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
    )
    assert r.ok is False
    assert r.verdict == "structural_ok"
    assert "no Bitcoin attestation" in r.note


def test_pole_python_stdlib_rejects_receipt_for_a_different_root(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    r = p.pole_python_stdlib_verify(
        anchor_hash="b" * 64,
        ots_proof_path=str(receipt),
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert "does not attest this root" in r.note


def test_pole_python_stdlib_rejects_text_shaped_non_proof(tmp_path):
    """The reviewer's counter-example, at the pole level."""
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
    )
    assert r.ok is False
    assert r.verdict == "failed"


def test_pole_python_stdlib_rejects_pending_text_shaped_non_proof(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(RECEIPT_PENDING_BYTES)
    r = p.pole_python_stdlib_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=948183,
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert "not a readable OpenTimestamps receipt" in r.note


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
    receipt.write_bytes(_receipt_bytes())
    runner = make_ots_runner(
        stdout="error: malformed receipt", returncode=1
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        ots_runner=runner,
    )
    assert r.ok is False
    assert r.verdict == "failed"
    # Note wording changed with the R3 fix: the pole now names the
    # subcommand it ran, because which one it ran was the defect.
    assert "ots verify rejected the timestamp (returncode 1)" in r.note


def test_pole_ots_cli_unavailable_marker_is_not_a_failure(tmp_path):
    """"Could not check" and "checked and wrong" are different answers.

    Upstream exits 1 both when a timestamp is bad and when it cannot
    reach a Bitcoin node. Reporting the second as ``failed`` would make
    every node-less host look like a tamper alarm; reporting it as
    ``verified`` would be the R3 defect again. It is ``unavailable``.
    """
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    runner = make_ots_runner(
        stdout="Could not connect to Bitcoin node: Cookie file unusable",
        returncode=1,
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        ots_runner=runner,
    )
    assert r.ok is False
    assert r.verdict == "unavailable"


def test_pole_ots_cli_digest_mismatch_retries_then_fails(tmp_path):
    """Both accepted bindings are offered before the pole gives up."""
    seen: list[list[str]] = []

    def runner(argv):
        seen.append(list(argv))

        class _CP:
            stdout = ""
            stderr = (
                "Digest provided does not match digest in timestamp, "
                "aaaa (sha256)"
            )
            returncode = 1

        return _CP()

    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        ots_runner=runner,
    )
    assert r.ok is False
    assert r.verdict == "failed"
    assert len(seen) == 2, seen
    assert seen[0][1] == "verify" and seen[0][2] == "-d"
    assert seen[0][3] != seen[1][3]


def test_pole_ots_cli_info_mode_is_supporting_and_never_verified(tmp_path):
    """``ots info`` displays a timestamp; it does not verify one."""
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    runner = make_ots_runner(
        stdout="BitcoinBlockHeaderAttestation(948183)\n",
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        ots_runner=runner,
        mode=p.OTS_MODE_INFO,
    )
    assert r.ok is True
    assert r.verdict == "structural_ok"
    assert r.role == "supporting"
    assert r.is_root_bound is False


def test_pole_ots_cli_height_mismatch(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
    runner = make_ots_runner(
        stdout="BitcoinBlockHeaderAttestation(948183)\n",
    )
    r = p.pole_ots_cli_verify(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        expected_block_height=999_999,
        ots_runner=runner,
        mode=p.OTS_MODE_INFO,
    )
    assert r.ok is False
    assert "expected height" in r.note


def test_pole_ots_cli_missing_binary_is_unavailable(tmp_path):
    receipt = tmp_path / "r.ots"
    receipt.write_bytes(_receipt_bytes())
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
