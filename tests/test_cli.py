# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""CLI-level smoke tests for the ``wakir-verify`` console script.

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

from tests.fixtures import build_ots_receipt, receipt_file_digest


ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"


def _make_receipt(tmp_path):
    p = tmp_path / "root.bin.ots"
    p.write_bytes(
        build_ots_receipt(
            file_digest=receipt_file_digest(ANCHOR_HEX),
            branches=[{"ops": [], "attestation": ("bitcoin", 948183)}],
        )
    )
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
    # The pole detail moved under "anchor_verification": it is
    # evidence for the root-authenticity claim, not the report itself.
    poles = body["anchor_verification"]["pole_results"]
    assert "pole_python_stdlib" in poles
    assert "pole_ots_cli" in poles
    assert "pole_mempool_space" not in poles
    assert "pole_esplora_blockstream" not in poles
    # Offline, with no block header and no manifest: nothing is
    # contradicted and nothing is established. Exit 4, not 0.
    assert body["overall_status"] == "not_checked"
    assert rc == 4


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
    assert body["anchor_verification"]["quorum_policy"] == "2-of-4"


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
    poles = body["anchor_verification"]["pole_results"]
    assert "pole_ots_cli" not in poles
    assert "pole_python_stdlib" in poles
