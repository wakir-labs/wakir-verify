# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Multi-pole determinism + discrepancy audit (Sprint-8 Tag-3).

The Position-Paper §L4-References annex claims that four independent
implementations agree byte-precisely on a valid OTS-anchor proof.
Sprint-8 Tag-1 shipped the surface, Tag-2 shipped a live capture
against block 948183. Tag-3 hardens the cross-library claim with two
audit axes:

1.  **Determinism.** Re-running the verifier on the same input must
    produce a bit-identical :class:`AnchorVerification` payload. A
    pole that quietly carried a wall-clock timestamp or a dict-order
    artefact into its witness would weaken the brand-proof contract:
    an auditor who replays the saved witness JSON six months later
    must get the same answer.

2.  **Discrepancy handling.** When two poles disagree on substance,
    the aggregator must surface the disagreement in a structured way
    so an auditor can read the verdict + the divergence pattern
    without flattening pole_results by hand. The Tag-3 helper
    :func:`summarise_discrepancies` provides the structured report.

Test-vector matrix (TV-DET-*):

* **TV-DET-1 — verifier output is run-deterministic.**
  Replay the live 2026-05-13 capture twenty times. Every
  ``AnchorVerification.to_dict()`` must serialise to bit-identical
  JSON. Catches dict-order leaks, wall-clock leaks, random-id leaks.

* **TV-DET-2 — pole witness dicts are stable across re-runs.**
  Same fixture, five re-runs. Compare each per-pole witness dict
  bit-for-bit. Catches per-pole non-determinism (e.g. a pole
  caching a wall-clock into ``witness``).

* **TV-DET-3 — parser layer is property-stable (parser
  determinism).**
  Property test (stdlib pseudo-random, fifty seeds): build an
  ``ots info``-style text with a random valid block height, feed
  it through ``_extract_heights_from_text`` twice, must agree.
  Stand-in for "different library versions of the parser do not
  drift" when full multi-version Hypothesis testing is not
  practical (no Hypothesis in the runtime; no parallel-installed
  ``python-bitcoinlib`` versions on the test host).

* **TV-DET-4 — discrepancy summary, all-green case.**
  All four poles ``ok=True`` with identical observed_block_hash
  and heights. ``summarise_discrepancies`` returns
  ``severity="none"`` with no disagreement markers.

* **TV-DET-5 — discrepancy summary, 3-of-4 silent-error.**
  Three poles ``ok=True``, one pole ``unavailable`` (HTTP 503).
  Quorum-pass under default 3-of-4, ``severity="silent-minority"``,
  the unavailable pole is named in ``unavailable_poles``.

* **TV-DET-6 — discrepancy summary, 3-of-4 with substance
  contradiction.**
  Three poles ``ok=True`` (offline + one HTTP), one pole
  ``failed`` (HTTP pole observed a different hash). Quorum-pass
  under 3-of-4 but ``severity="substance"`` and the failed pole
  is named in ``failed_poles``; ``hash_disagreement=False``
  because only one ``ok`` HTTP pole remains (no inter-``ok``
  disagreement).

* **TV-DET-7 — discrepancy summary, brand-critical 2-of-4 failure.**
  Two poles ``failed`` (both HTTP poles report a chain-reorg
  hash), two poles ``ok``. Quorum-fail. ``severity="brand-critical"``
  is the marker the brand-proof contract calls out.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from wakir_verify import (
    AnchorVerification,
    summarise_discrepancies,
    verify_wat_anchor,
)
from wakir_verify.poles import _extract_heights_from_text

from tests.fixtures import (
    RECEIPT_948183_BYTES,
    make_http_transport,
    make_ots_runner,
    make_proof_reader,
)


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"
WITNESS_DIR = Path(__file__).parent / "fixtures" / "witness_captures"
LIVE_CAPTURE = WITNESS_DIR / "2026-05-13-block-948183.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_receipt(tmp_path, blob: bytes = RECEIPT_948183_BYTES) -> Path:
    p = tmp_path / "root.bin.ots"
    p.write_bytes(blob)
    return p


def _load_live_capture() -> dict:
    return json.loads(LIVE_CAPTURE.read_text())


def _overrides_from_live(captured: dict) -> dict:
    """Build aggregator pole_overrides from the live witness capture.

    Distinct from the helper in :mod:`test_witness_captures` so the
    determinism tests stay decoupled: any future change to the
    Tag-2 helper must not silently change Tag-3 expectations.
    """
    height = captured["block_height"]
    canonical_hash = captured["pole_witnesses"][
        "pole_esplora_blockstream"
    ]["witness"]["observed_block_hash"]
    return {
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
        "pole_mempool_space": {
            "expected_block_height": height,
            "expected_block_hash": canonical_hash,
            "transport": make_http_transport(
                block_hash_by_height={height: canonical_hash},
            ),
        },
        "pole_esplora_blockstream": {
            "expected_block_height": height,
            "expected_block_hash": canonical_hash,
            "transport": make_http_transport(
                block_hash_by_height={height: canonical_hash},
            ),
        },
    }


def _serialise(verification: AnchorVerification) -> str:
    """Deterministic JSON serialisation for bit-equality checks.

    ``sort_keys=True`` defeats dict-order non-determinism in
    Python's JSON encoder; ``separators`` pins whitespace.
    """
    return json.dumps(
        verification.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    )


# ---------------------------------------------------------------------------
# TV-DET-1: verifier output is run-deterministic across many re-runs
# ---------------------------------------------------------------------------


def test_tv_det_1_verifier_output_deterministic_across_runs(tmp_path):
    captured = _load_live_capture()
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_live(captured)

    serialisations: list[str] = []
    for _ in range(20):
        result = verify_wat_anchor(
            anchor_hash=ANCHOR_HEX,
            ots_proof_path=str(receipt),
            pole_overrides=overrides,
        )
        assert result.quorum is True
        serialisations.append(_serialise(result))

    # All twenty serialisations must be bit-identical.
    distinct = set(serialisations)
    assert len(distinct) == 1, (
        f"verifier output drifted across re-runs; saw "
        f"{len(distinct)} distinct serialisations: {distinct}"
    )


# ---------------------------------------------------------------------------
# TV-DET-2: per-pole witness dicts are stable across re-runs
# ---------------------------------------------------------------------------


def test_tv_det_2_pole_witnesses_stable_across_reruns(tmp_path):
    captured = _load_live_capture()
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_live(captured)

    first = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    baseline = {
        name: json.dumps(dict(pr.witness), sort_keys=True)
        for name, pr in first.pole_results.items()
    }

    for run_idx in range(5):
        result = verify_wat_anchor(
            anchor_hash=ANCHOR_HEX,
            ots_proof_path=str(receipt),
            pole_overrides=overrides,
        )
        for name, pr in result.pole_results.items():
            current = json.dumps(dict(pr.witness), sort_keys=True)
            assert current == baseline[name], (
                f"pole {name!r} witness drifted on run {run_idx}: "
                f"baseline={baseline[name]!r} current={current!r}"
            )


# ---------------------------------------------------------------------------
# TV-DET-3: parser-layer property test (stdlib pseudo-random)
# ---------------------------------------------------------------------------


def test_tv_det_3_parser_layer_property_stable():
    """Parser-layer determinism over fifty random seeds.

    Hypothesis is not available in the runtime test-env (boring-tech
    bias: zero PyPI-surface for the brand-proof verifier). We do the
    equivalent with stdlib ``random.Random(seed)`` over fifty seeds:
    build a synthetic ``ots info``-style text, feed it through
    ``_extract_heights_from_text`` twice, must agree.

    The intent is to catch a future regression where the parser
    grows a non-deterministic dependency (e.g. set-order, dict
    insertion-order on Python <3.7 — not applicable on current
    targets but the test pins the contract).
    """
    for seed in range(50):
        rng = random.Random(seed)
        # Build between 1 and 4 random block-height attestations
        # interleaved with random non-matching noise lines.
        n_heights = rng.randint(1, 4)
        heights = [rng.randint(1, 999_999_999) for _ in range(n_heights)]
        lines: list[str] = []
        for h in heights:
            # Alternate between the two regex shapes the parser supports.
            if rng.random() < 0.5:
                lines.append(f"BitcoinBlockHeaderAttestation({h})")
            else:
                lines.append(f"Bitcoin block {h}")
            # Random noise line that must not match.
            lines.append(f"noise-line-{rng.randint(0, 1_000_000)}")
        text = "\n".join(lines)

        first = _extract_heights_from_text(text)
        second = _extract_heights_from_text(text)
        assert first == second, (
            f"parser non-deterministic on seed {seed}: "
            f"first={first} second={second} text={text!r}"
        )
        # First-seen order must be preserved and dedup must hold.
        seen: list[int] = []
        for h in heights:
            if h not in seen:
                seen.append(h)
        assert first == seen, (
            f"parser output diverged from expected first-seen-order "
            f"on seed {seed}: got={first} expected={seen}"
        )


# ---------------------------------------------------------------------------
# TV-DET-4: discrepancy summary — all green
# ---------------------------------------------------------------------------


def test_tv_det_4_discrepancy_summary_all_green(tmp_path):
    captured = _load_live_capture()
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_live(captured)

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert result.quorum is True

    summary = summarise_discrepancies(result)
    assert summary["severity"] == "none"
    assert summary["hash_disagreement"] is False
    assert summary["height_disagreement"] is False
    assert summary["failed_poles"] == []
    assert summary["unavailable_poles"] == []
    assert set(summary["ok_poles"]) == set(result.pole_results.keys())


# ---------------------------------------------------------------------------
# TV-DET-5: discrepancy summary — 3-of-4 with one silent (unavailable)
# ---------------------------------------------------------------------------


def test_tv_det_5_discrepancy_summary_silent_minority(tmp_path):
    captured = _load_live_capture()
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_live(captured)
    # Replace pole_mempool_space transport with a 503-returning one.
    height = captured["block_height"]
    overrides["pole_mempool_space"]["transport"] = make_http_transport(
        block_hash_by_height={},
        failure_status_for_heights={height: 503},
    )

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    # 3-of-4 default still passes (offline poles + blockstream).
    assert result.quorum is True
    mempool = result.pole_results["pole_mempool_space"]
    assert mempool.ok is False
    assert mempool.verdict == "unavailable"

    summary = summarise_discrepancies(result)
    assert summary["severity"] == "silent-minority"
    assert summary["failed_poles"] == []
    assert "pole_mempool_space" in summary["unavailable_poles"]
    # The remaining ok-poles agree on substance (one HTTP pole left,
    # so no inter-ok disagreement possible).
    assert summary["hash_disagreement"] is False
    assert summary["height_disagreement"] is False


# ---------------------------------------------------------------------------
# TV-DET-6: discrepancy summary — 3-of-4 with substance contradiction
# ---------------------------------------------------------------------------


def test_tv_det_6_discrepancy_summary_substance_contradiction(tmp_path):
    captured = _load_live_capture()
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_live(captured)
    # Make pole_mempool_space observe a tampered hash; the pin is
    # the canonical blockstream hash, so this pole flips to failed
    # (verdict=failed, not unavailable).
    height = captured["block_height"]
    TAMPERED_HASH = (
        "00000000000000000000ec730435b01d9bdd9de0a10f1a8c4a33ea27e52b21ff"
    )
    overrides["pole_mempool_space"]["transport"] = make_http_transport(
        block_hash_by_height={height: TAMPERED_HASH},
    )

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    # 3-of-4 still passes.
    assert result.quorum is True
    mempool = result.pole_results["pole_mempool_space"]
    assert mempool.ok is False
    assert mempool.verdict == "failed"

    summary = summarise_discrepancies(result)
    assert summary["severity"] == "substance", (
        f"expected severity=substance, got {summary['severity']!r}; "
        f"summary={summary}"
    )
    assert "pole_mempool_space" in summary["failed_poles"]
    assert summary["unavailable_poles"] == []
    # Only one HTTP pole remains in ok_poles, so no inter-ok hash
    # disagreement; the failed pole carries the substance flag via
    # its verdict.
    assert summary["hash_disagreement"] is False


# ---------------------------------------------------------------------------
# TV-DET-7: discrepancy summary — brand-critical 2-of-4 failure
# ---------------------------------------------------------------------------


def test_tv_det_7_discrepancy_summary_brand_critical(tmp_path):
    captured = _load_live_capture()
    receipt = _write_receipt(tmp_path)
    overrides = _overrides_from_live(captured)
    # Both HTTP poles observe a chain-reorg hash; both flip to failed.
    height = captured["block_height"]
    REORG_HASH = (
        "00000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    reorg_transport = make_http_transport(
        block_hash_by_height={height: REORG_HASH},
    )
    overrides["pole_mempool_space"]["transport"] = reorg_transport
    overrides["pole_esplora_blockstream"]["transport"] = reorg_transport

    result = verify_wat_anchor(
        anchor_hash=ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    # 2-of-4 ok; 3-of-4 quorum FAILS.
    assert result.quorum is False
    for http_pole in ("pole_mempool_space", "pole_esplora_blockstream"):
        pr = result.pole_results[http_pole]
        assert pr.ok is False
        assert pr.verdict == "failed"

    summary = summarise_discrepancies(result)
    assert summary["severity"] == "brand-critical", (
        f"expected severity=brand-critical, got {summary['severity']!r}; "
        f"summary={summary}"
    )
    assert set(summary["failed_poles"]) == {
        "pole_mempool_space",
        "pole_esplora_blockstream",
    }
    assert set(summary["ok_poles"]) == {
        "pole_python_stdlib",
        "pole_ots_cli",
    }
    assert summary["unavailable_poles"] == []
