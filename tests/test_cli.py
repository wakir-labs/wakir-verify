# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""CLI-level smoke tests for ``wat-verify``.

We do not exercise the HTTP poles end-to-end here (those need
transport injection that the argparse surface does not expose);
this suite covers the offline-only quorum path and the
"--skip-pole" trim behaviour. End-to-end with HTTP poles lives in
``test_aggregator.py`` via the public function.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from wakir_verify.cli import main as cli_main

from tests.fixtures import RECEIPT_948183_BYTES


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"


def _make_receipt(tmp_path):
    p = tmp_path / "root.bin.ots"
    p.write_bytes(RECEIPT_948183_BYTES)
    return p


def _run_cli(argv, capsys) -> tuple[int, dict]:
    rc = cli_main(argv)
    captured = capsys.readouterr()
    body = json.loads(captured.out) if captured.out.strip() else {}
    return rc, body


def test_cli_offline_only_without_expected_height_trims_http_poles(
    tmp_path, capsys
):
    """No --expected-block-height -> HTTP poles trimmed; offline-only verdict."""
    receipt = _make_receipt(tmp_path)
    rc, body = _run_cli(
        ["--anchor", ANCHOR_HEX, "--ots-proof", str(receipt)],
        capsys,
    )
    # Structural pole has no expected_block_height -> structural-only
    # acceptance based on the bytes containing a height-attestation
    # marker. Receipt fixture contains 948183, so structural pole
    # passes. OTS-CLI pole: real binary on PATH? Tests should not
    # depend on that. We pass --skip-pole-implicit by relying on the
    # ots binary being absent in CI: assert structural pole is in,
    # ots-cli pole reported (ok or unavailable), HTTP poles absent.
    assert "pole_python_stdlib" in body["pole_results"]
    assert "pole_ots_cli" in body["pole_results"]
    assert "pole_mempool_space" not in body["pole_results"]
    assert "pole_esplora_blockstream" not in body["pole_results"]


def test_cli_skip_all_poles_is_usage_error(tmp_path, capsys):
    receipt = _make_receipt(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        cli_main(
            [
                "--anchor",
                ANCHOR_HEX,
                "--ots-proof",
                str(receipt),
                "--skip-pole",
                "pole_python_stdlib",
                "--skip-pole",
                "pole_ots_cli",
                "--skip-pole",
                "pole_mempool_space",
                "--skip-pole",
                "pole_esplora_blockstream",
            ]
        )
    # argparse.error -> SystemExit(2)
    assert excinfo.value.code == 2


def test_cli_bad_anchor_hash_is_usage_error(tmp_path, capsys):
    receipt = _make_receipt(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        cli_main(
            [
                "--anchor",
                "not-hex",
                "--ots-proof",
                str(receipt),
            ]
        )
    assert excinfo.value.code == 2


def test_cli_quorum_policy_passthrough(tmp_path, capsys):
    receipt = _make_receipt(tmp_path)
    rc, body = _run_cli(
        [
            "--anchor",
            ANCHOR_HEX,
            "--ots-proof",
            str(receipt),
            "--pols",
            "2-of-4",
        ],
        capsys,
    )
    assert body["quorum_policy"] == "2-of-4"


def test_cli_skip_pole_ots_cli(tmp_path, capsys):
    """Allow operators to skip the ots CLI pole on hosts without the binary."""
    receipt = _make_receipt(tmp_path)
    rc, body = _run_cli(
        [
            "--anchor",
            ANCHOR_HEX,
            "--ots-proof",
            str(receipt),
            "--skip-pole",
            "pole_ots_cli",
        ],
        capsys,
    )
    assert "pole_ots_cli" not in body["pole_results"]
    assert "pole_python_stdlib" in body["pole_results"]
