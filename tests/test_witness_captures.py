# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Witness-capture fixture-replay test suite (Sprint-8 Tag-2).

These tests pin the contract between the saved witness-capture JSON
files under ``tests/fixtures/witness_captures/`` and the
4-pole aggregator. The witness-capture files are the brand-proof
artefacts a third-party auditor receives alongside the OTS receipt;
the aggregator must be able to replay them deterministically without
re-touching mempool.space or blockstream.info.

Test-vector matrix:

* **TV-WC-1 — live-capture replay, quorum-pass**
  Replays the live 2026-05-13 capture against block 948183. The
  saved canonical hash from both HTTP poles is the same as the
  Tag-15 ``docs/wat-tv1-live-run-2026-05-07.md`` recorded hash, so
  the offline-replay 4-pole quorum verifies under default 3-of-4.

* **TV-WC-2 — live-capture replay, strict-policy passes**
  Same fixture, ``--pols all`` policy. Live capture has no failing
  poles, so the strict quorum also passes.

* **TV-WC-3 — mock-divergence, quorum-fail edge**
  Replays the mock-divergence fixture: pole_mempool_space's saved
  hash has been mutated by one nibble. When replayed against the
  ``expected_block_hash`` recorded by pole_esplora_blockstream, the
  mempool pole flips to ``failed``. Under 3-of-4, three poles
  still verify (offline poles + blockstream) -> quorum-pass with
  visible divergence. Under ``all`` policy -> quorum-fail.

* **TV-WC-4 — partial-witness, one HTTP pole synthetic 503**
  Replays the live capture but injects a transport that returns 503
  on the second pole, simulating a real-world transient outage
  during the replay. Default 3-of-4 still passes (offline poles +
  one HTTP pole verify); strict ``all`` policy fails.

* **TV-WC-5 — expired-witness edge case**
  Simulates the auditor-replay-much-later scenario: the saved
  canonical hash and the "current" Esplora response disagree
  (chain reorg simulation). Both HTTP poles return a different
  hash than the saved capture, so both flip to ``failed``.
  Quorum-fail under all policies because the cross-library
  contract reads "the saved witness diverged from current chain"
  as evidence the saved capture must be re-examined.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wakir_verify import (
    AnchorVerification,
    QuorumPolicy,
    verify_wat_anchor,
)
from wakir_verify.poles import HttpResponse

from tests.fixtures import (
    RECEIPT_948183_BYTES,
    make_http_transport,
    make_ots_runner,
    make_proof_reader,
)


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"
WITNESS_DIR = Path(__file__).parent / "fixtures" / "witness_captures"
LIVE_CAPTURE = WITNESS_DIR / "2026-05-13-block-948183.json"
MOCK_DIVERGENCE_CAPTURE = WITNESS_DIR / "2026-05-13-block-948183-tampered-mock.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_receipt(tmp_path, blob: bytes = RECEIPT_948183_BYTES) -> Path:
    p = tmp_path / "root.bin.ots"
    p.write_bytes(blob)
    return p


def _load_capture(path: Path) -> dict:
    return json.loads(path.read_text())


def _overrides_from_capture(
    captured: dict,
    *,
    use_recorded_block_hash: bool = True,
    transport_overrides: dict | None = None,
) -> dict:
    """Build aggregator pole_overrides from a saved witness capture.

    ``use_recorded_block_hash`` toggles assertion vs. witness-capture
    mode: when True the HTTP poles assert equality against the saved
    canonical hash; when False they only record the observed hash.

    ``transport_overrides`` lets a single test inject an alternative
    transport for one named pole, leaving the other pole's transport
    pinned to the saved-capture-replay fake.
    """
    height = captured["block_height"]
    overrides: dict = {
        "pole_python_stdlib": {
            "expected_block_height": height,
            "proof_reader": make_proof_reader(
                merkle_root_hex=ANCHOR_HEX,
                heights=[height],
            ),
        },
        "pole_ots_cli": {
            "expected_block_height": height,
            "ots_runner": make_ots_runner(
                stdout=f"BitcoinBlockHeaderAttestation({height})\n",
            ),
        },
    }

    transport_overrides = transport_overrides or {}
    for pole_name in ("pole_mempool_space", "pole_esplora_blockstream"):
        pole_witness = captured["pole_witnesses"][pole_name]["witness"]
        observed_hash = pole_witness["observed_block_hash"]
        # The HTTP pole's expected_block_hash is the canonical pinned
        # value: when replaying against the live capture the pin is the
        # same as the observed hash; for the divergence test we use the
        # canonical blockstream-observed hash as the pin and let
        # mempool's mutated hash flip the pole to failed.
        if use_recorded_block_hash:
            canonical = captured["pole_witnesses"][
                "pole_esplora_blockstream"
            ]["witness"]["observed_block_hash"]
            expected_hash = canonical
        else:
            expected_hash = None

        if pole_name in transport_overrides:
            transport = transport_overrides[pole_name]
        else:
            # Default: replay-transport returns the saved canonical hash.
            transport = make_http_transport(
                block_hash_by_height={height: observed_hash},
            )
        overrides[pole_name] = {
            "expected_block_height": height,
            "expected_block_hash": expected_hash,
            "transport": transport,
        }
    return overrides


# ---------------------------------------------------------------------------
# Fixture-presence sanity
# ---------------------------------------------------------------------------


def test_witness_capture_dir_has_documented_files():
    """The witness_captures dir must hold the brand-demo and mock files."""
    assert LIVE_CAPTURE.exists(), (
        "live-capture fixture missing; expected the 2026-05-13 capture "
        "against block 948183 to be checked in."
    )
    assert MOCK_DIVERGENCE_CAPTURE.exists(), (
        "mock-divergence fixture missing; expected the explicit-mock "
        "tampered-witness companion to be checked in."
    )
    mock = _load_capture(MOCK_DIVERGENCE_CAPTURE)
    assert "_comment_mock_marker" in mock, (
        "mock-divergence file must carry a top-level _comment_mock_marker "
        "key; auditors look for this exact marker to know the file is "
        "not an authoritative live capture."
    )


# ---------------------------------------------------------------------------
# TV-WC-1: live-capture quorum-pass
# ---------------------------------------------------------------------------


def test_tv_wc_1_live_capture_quorum_pass(tmp_path):
    captured = _load_capture(LIVE_CAPTURE)
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_capture(captured)

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert isinstance(result, AnchorVerification)
    assert result.quorum is True
    for name, pr in result.pole_results.items():
        assert pr.ok is True, f"{name} did not verify: {pr.note}"
        assert pr.verdict == "verified", (name, pr.verdict)


# ---------------------------------------------------------------------------
# TV-WC-2: live-capture strict-all-policy still passes
# ---------------------------------------------------------------------------


def test_tv_wc_2_live_capture_strict_all_policy_passes(tmp_path):
    captured = _load_capture(LIVE_CAPTURE)
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_capture(captured)

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.ALL,
        pole_overrides=overrides,
    )
    assert result.quorum is True


# ---------------------------------------------------------------------------
# TV-WC-3: mock-divergence — pole disagreement, 3-of-4 passes, ALL fails
# ---------------------------------------------------------------------------


def test_tv_wc_3_mock_divergence_passes_default_quorum_fails_strict(tmp_path):
    captured = _load_capture(MOCK_DIVERGENCE_CAPTURE)
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_capture(captured)

    default = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    # mempool pole sees the mutated hash, expected pin is the
    # blockstream-canonical hash -> mempool flips to failed.
    assert default.pole_results["pole_mempool_space"].ok is False
    assert default.pole_results["pole_mempool_space"].verdict == "failed"
    # Three poles still ok -> 3-of-4 quorum passes (with visible
    # divergence surfaced in pole_results).
    assert default.quorum is True

    strict = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.ALL,
        pole_overrides=overrides,
    )
    assert strict.quorum is False


# ---------------------------------------------------------------------------
# TV-WC-4: partial-witness replay — one HTTP pole 503 during replay
# ---------------------------------------------------------------------------


def test_tv_wc_4_partial_witness_during_replay(tmp_path):
    captured = _load_capture(LIVE_CAPTURE)
    receipt = _write_receipt(tmp_path)

    # Inject a transport that returns 503 on mempool but normal on
    # blockstream — this is the realistic "auditor reruns later, one
    # endpoint is having a bad day" scenario.
    failing_transport = make_http_transport(
        block_hash_by_height={},
        failure_status_for_heights={948183: 503},
    )
    overrides = _overrides_from_capture(
        captured,
        transport_overrides={"pole_mempool_space": failing_transport},
    )

    default = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert default.pole_results["pole_mempool_space"].ok is False
    assert default.pole_results["pole_mempool_space"].verdict == "unavailable"
    assert default.pole_results["pole_esplora_blockstream"].ok is True
    # 3/4 poles ok (two offline + blockstream) -> default quorum passes.
    assert default.quorum is True

    strict = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        quorum_policy=QuorumPolicy.ALL,
        pole_overrides=overrides,
    )
    assert strict.quorum is False


# ---------------------------------------------------------------------------
# TV-WC-5: expired-witness edge — replay where chain disagrees with saved
# ---------------------------------------------------------------------------


def test_tv_wc_5_expired_witness_chain_reorg_simulation(tmp_path):
    """Both HTTP poles report a different canonical hash than the saved one.

    This is the chain-reorg simulation: months later, an auditor reruns
    the verifier and the live Esplora endpoints have a different hash
    for the same height (e.g. the saved capture was wrong, or a deep
    reorg invalidated it, or — more realistically — the saved file
    was tampered with after the fact). Both HTTP poles flip to
    ``failed`` and the verification correctly raises an audit failure.
    """
    captured = _load_capture(LIVE_CAPTURE)
    receipt = _write_receipt(tmp_path)
    # Build the override against the saved capture's pinned hash, but
    # override the transports to return a *different* hash. This mirrors
    # the operator-host scenario where the receipt and saved-witness
    # come from one source-of-truth and the replay endpoints diverge.
    saved_canonical = captured["pole_witnesses"][
        "pole_esplora_blockstream"
    ]["witness"]["observed_block_hash"]
    REORG_HASH = (
        "00000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert REORG_HASH != saved_canonical
    reorg_transport = make_http_transport(
        block_hash_by_height={948183: REORG_HASH},
    )

    overrides = _overrides_from_capture(
        captured,
        transport_overrides={
            "pole_mempool_space": reorg_transport,
            "pole_esplora_blockstream": reorg_transport,
        },
    )
    # The expected_block_hash pin in overrides is still the saved
    # canonical hash; both HTTP poles observe the reorg hash; both fail.

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    for http_pole in ("pole_mempool_space", "pole_esplora_blockstream"):
        pr = result.pole_results[http_pole]
        assert pr.ok is False, (http_pole, pr.note)
        assert pr.verdict == "failed", (http_pole, pr.verdict)
    # Offline poles still happy; 2/4 ok, default 3-of-4 fails.
    assert result.quorum is False
