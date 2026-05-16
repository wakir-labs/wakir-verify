# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Aggregator-level tests for the 4-pole external verifier.

These tests cover the cross-library contract: quorum policy
semantics, per-pole error handling, and the public API shape that
the Position-Paper §L4 annex pins. Pole-internal behaviour
(structural OTS-receipt parsing, HTTP transport error mapping,
``ots`` CLI output parsing) lives in ``test_poles.py``.
"""

from __future__ import annotations

import json

import pytest

from wakir_verify import (
    AnchorVerification,
    QuorumPolicy,
    verify_wat_anchor,
)

from tests.fixtures import (
    BLOCK_HASH_948183,
    RECEIPT_948183_BYTES,
    make_http_transport,
    make_ots_runner,
    make_proof_reader,
)


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"
WRONG_ANCHOR_HEX = "deadbeef" * 8  # 64 hex chars, structurally valid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_receipt(tmp_path, blob: bytes = RECEIPT_948183_BYTES):
    p = tmp_path / "root.bin.ots"
    p.write_bytes(blob)
    return p


def _all_poles_happy_overrides(anchor_hex: str = ANCHOR_HEX) -> dict:
    return {
        "pole_python_stdlib": {
            "expected_block_height": 948183,
            "proof_reader": make_proof_reader(
                merkle_root_hex=anchor_hex,
                heights=[948183],
            ),
        },
        "pole_ots_cli": {
            "expected_block_height": 948183,
            "ots_runner": make_ots_runner(
                stdout="BitcoinBlockHeaderAttestation(948183)\n",
            ),
        },
        "pole_mempool_space": {
            "expected_block_height": 948183,
            "expected_block_hash": BLOCK_HASH_948183,
            "transport": make_http_transport(
                block_hash_by_height={948183: BLOCK_HASH_948183},
            ),
        },
        "pole_esplora_blockstream": {
            "expected_block_height": 948183,
            "expected_block_hash": BLOCK_HASH_948183,
            "transport": make_http_transport(
                block_hash_by_height={948183: BLOCK_HASH_948183},
            ),
        },
    }


# ---------------------------------------------------------------------------
# TV-EV-1: known-good-anchor — all four poles verify
# ---------------------------------------------------------------------------


def test_tv_ev_1_known_good_anchor_default_quorum(tmp_path):
    receipt = _write_receipt(tmp_path)
    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=_all_poles_happy_overrides(),
    )
    assert isinstance(result, AnchorVerification)
    assert result.quorum is True
    assert result.quorum_policy == QuorumPolicy.THREE_OF_FOUR
    assert all(pr.ok for pr in result.pole_results.values()), result.to_dict()
    assert all(
        pr.verdict == "verified" for pr in result.pole_results.values()
    ), result.to_dict()


def test_tv_ev_1_known_good_anchor_strict_all_policy(tmp_path):
    receipt = _write_receipt(tmp_path)
    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.ALL,
        pole_overrides=_all_poles_happy_overrides(),
    )
    assert result.quorum is True  # all four poles still happy


# ---------------------------------------------------------------------------
# TV-EV-2: tampered anchor hash — proof_reader rejects, HTTP poles still
# observe the canonical block hash (which is height-keyed, not
# anchor-keyed) — quorum must still fail because pole 1 + pole 2 reject.
# ---------------------------------------------------------------------------


def test_tv_ev_2_tampered_anchor_fails_quorum(tmp_path):
    receipt = _write_receipt(tmp_path)
    # Caller asserts a wrong anchor hex; injected proof_reader will
    # report the receipt's actual root, which differs.
    overrides = _all_poles_happy_overrides(anchor_hex=ANCHOR_HEX)
    # pole_python_stdlib's proof_reader is the seam: it reports the
    # real merkle root, the caller's anchor argument is wrong, so
    # pole_python_stdlib rejects.
    result = verify_wat_anchor(
        anchor_hash=WRONG_ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert result.pole_results["pole_python_stdlib"].ok is False
    assert result.pole_results["pole_python_stdlib"].verdict == "failed"
    # ots-cli pole sees the right height -> ok=True (it does not check
    # the merkle root, that's the structural pole's job).
    assert result.pole_results["pole_ots_cli"].ok is True
    # HTTP poles check expected_block_hash, which is still BLOCK_HASH_948183
    # for height 948183 -> ok=True.
    assert result.pole_results["pole_mempool_space"].ok is True
    assert result.pole_results["pole_esplora_blockstream"].ok is True
    # 3-of-4 quorum: three poles still ok, but the structural-hash
    # pole flagged a tamper. Under default policy this passes quorum
    # but the operator-visible AnchorVerification surfaces the
    # disagreement.
    assert result.quorum is True  # 3/4 ok
    # Under ALL policy the same call must fail:
    strict = verify_wat_anchor(
        anchor_hash=WRONG_ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.ALL,
        pole_overrides=overrides,
    )
    assert strict.quorum is False
    assert strict.pole_results["pole_python_stdlib"].ok is False


# ---------------------------------------------------------------------------
# TV-EV-3: wrong-height tamper — two poles reject, quorum fails
# ---------------------------------------------------------------------------


def test_tv_ev_3_wrong_height_tamper(tmp_path):
    receipt = _write_receipt(tmp_path)
    overrides = _all_poles_happy_overrides()
    # Caller claims height 999_999 across all poles
    for name in (
        "pole_python_stdlib",
        "pole_ots_cli",
        "pole_mempool_space",
        "pole_esplora_blockstream",
    ):
        overrides[name]["expected_block_height"] = 999_999
    # The HTTP transport only knows height 948183; for 999_999 it
    # returns 404 (=> pole returns unavailable). The OTS runner still
    # emits 948183 (=> pole rejects on height mismatch). Proof_reader
    # still reports heights=[948183] (=> pole rejects on height
    # mismatch).
    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert result.pole_results["pole_python_stdlib"].ok is False
    assert result.pole_results["pole_python_stdlib"].verdict == "failed"
    assert result.pole_results["pole_ots_cli"].ok is False
    assert result.pole_results["pole_ots_cli"].verdict == "failed"
    assert result.pole_results["pole_mempool_space"].ok is False
    assert result.pole_results["pole_mempool_space"].verdict == "unavailable"
    assert result.pole_results["pole_esplora_blockstream"].ok is False
    assert result.quorum is False


# ---------------------------------------------------------------------------
# TV-EV-4: partial-witness-quorum-pass — one HTTP pole down, 3/4 passes
# ---------------------------------------------------------------------------


def test_tv_ev_4_partial_witness_quorum_pass(tmp_path):
    receipt = _write_receipt(tmp_path)
    overrides = _all_poles_happy_overrides()
    # mempool.space returns 503 for the queried height
    overrides["pole_mempool_space"]["transport"] = make_http_transport(
        block_hash_by_height={},  # nothing answered
        failure_status_for_heights={948183: 503},
    )
    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert result.pole_results["pole_mempool_space"].ok is False
    assert result.pole_results["pole_mempool_space"].verdict == "unavailable"
    # Other three still happy
    assert result.pole_results["pole_python_stdlib"].ok is True
    assert result.pole_results["pole_ots_cli"].ok is True
    assert result.pole_results["pole_esplora_blockstream"].ok is True
    # 3-of-4 quorum passes
    assert result.quorum is True
    # ALL policy fails
    strict = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.ALL,
        pole_overrides=overrides,
    )
    assert strict.quorum is False


# ---------------------------------------------------------------------------
# TV-EV-5: both HTTP poles down — 2/4 default fails, 2-of-4 policy passes
# ---------------------------------------------------------------------------


def test_tv_ev_5_both_http_poles_down(tmp_path):
    receipt = _write_receipt(tmp_path)
    overrides = _all_poles_happy_overrides()
    for http_pole in ("pole_mempool_space", "pole_esplora_blockstream"):
        overrides[http_pole]["transport"] = make_http_transport(
            block_hash_by_height={},
            failure_status_for_heights={948183: 503},
        )
    default = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert default.quorum is False  # only 2/4 ok, default needs 3
    debug = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.TWO_OF_FOUR,
        pole_overrides=overrides,
    )
    assert debug.quorum is True


# ---------------------------------------------------------------------------
# Public-API hygiene
# ---------------------------------------------------------------------------


def test_anchor_hex_must_be_64_lowercase_hex(tmp_path):
    receipt = _write_receipt(tmp_path)
    with pytest.raises(ValueError):
        verify_wat_anchor(
            anchor_hash="not-hex",
            ots_proof_path=str(receipt),
        )
    with pytest.raises(ValueError):
        # uppercase not accepted
        verify_wat_anchor(
            anchor_hash=ANCHOR_HEX.upper(),
            ots_proof_path=str(receipt),
        )


def test_unknown_pole_name_rejected(tmp_path):
    receipt = _write_receipt(tmp_path)
    with pytest.raises(ValueError):
        verify_wat_anchor(
            anchor_hash=ANCHOR_HEX,
            ots_proof_path=str(receipt),
            enabled_poles=["does_not_exist"],
        )


def test_to_dict_serialisable(tmp_path):
    receipt = _write_receipt(tmp_path)
    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=_all_poles_happy_overrides(),
    )
    blob = json.dumps(result.to_dict())
    # Round-trip-cleanly through json.dumps -> json.loads
    round_tripped = json.loads(blob)
    assert round_tripped["anchor_hash"] == ANCHOR_HEX
    assert round_tripped["quorum"] is True
    assert set(round_tripped["pole_results"].keys()) == {
        "pole_python_stdlib",
        "pole_ots_cli",
        "pole_mempool_space",
        "pole_esplora_blockstream",
    }


def test_aggregator_never_crashes_on_pole_exception(tmp_path, monkeypatch):
    """A pole raising must downgrade to unavailable, never propagate."""
    from wakir_verify import aggregator as agg

    def _exploding_pole(**kwargs):
        raise RuntimeError("simulated pole crash")

    monkeypatch.setitem(agg.POLE_REGISTRY, "pole_python_stdlib", _exploding_pole)
    receipt = _write_receipt(tmp_path)
    overrides = _all_poles_happy_overrides()
    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    pr = result.pole_results["pole_python_stdlib"]
    assert pr.ok is False
    assert pr.verdict == "unavailable"
    assert "simulated pole crash" in pr.note
