# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""CLI text-mode and witness-capture mode tests.

Splits cleanly from ``test_cli.py``: that file pins the earlier increment's JSON-only
surface (default output-format=json), this one pins the text
renderer and the ``--capture-witnesses`` mode.

Brand-language pins (ADR-0055):

* Operator-Plattform wording — "operator endpoint", not "user app".
* Per-pole line carries a status symbol and the pole's substantive
  observation.
* Block-end "Conclusion" section states the verdict and, when the
  verdict is not positive, names what was not checked — so the
  external reviewer does not have to know the policy enum or infer
  scope from a single word.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wakir_verify.cli import main as cli_main
from wakir_verify.poles import HttpResponse

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


# ---------------------------------------------------------------------------
# Output-format=text
# ---------------------------------------------------------------------------


def test_cli_text_mode_renders_offline_quorum_block(tmp_path, capsys):
    """Text-mode output names every pole, status symbol, and conclusion."""
    receipt = _make_receipt(tmp_path)
    rc = cli_main(
        [
            "--anchor",
            ANCHOR_HEX,
            "--ots-proof",
            str(receipt),
            "--output-format",
            "text",
        ]
    )
    out = capsys.readouterr().out
    # Two offline poles ran (HTTP poles auto-trimmed; no expected height)
    assert "Pole 1" in out
    assert "Pole 2" in out
    # HTTP-pole labels should NOT appear because they were trimmed
    assert "Pole 3" not in out
    assert "Pole 4" not in out
    # Status symbols are ASCII
    assert "[+]" in out or "[-]" in out or "[?]" in out
    # Expectation changed with R2/R3: the closing block is the
    # four-claim conclusion. A run with no manifest, no payload and no
    # block header establishes none of the four, and the output has to
    # say which — a bare threshold line let a reader supply the rest.
    assert "Conclusion" in out
    assert "NOT VERIFIED" in out
    assert "Root authenticity" in out
    assert "NOT CHECKED" in out
    # Operator-Plattform wording — must not use consumer-app language
    assert "consumer" not in out.lower()
    assert "end-user" not in out.lower()
    assert "user app" not in out.lower()


def test_cli_text_mode_default_is_json_for_backwards_compat(tmp_path, capsys):
    """Original contract: omitting --output-format yields JSON, not text."""
    receipt = _make_receipt(tmp_path)
    rc = cli_main(
        ["--anchor", ANCHOR_HEX, "--ots-proof", str(receipt)]
    )
    out = capsys.readouterr().out
    # JSON output starts with '{' and parses cleanly
    body = json.loads(out)
    assert body["anchor_hash"] == ANCHOR_HEX
    # No human-text header should appear in JSON output
    assert "Conclusion" not in out


def test_cli_text_mode_carries_pole_substance(tmp_path, capsys):
    """Each pole gets a substance-sentence describing what it observed."""
    receipt = _make_receipt(tmp_path)
    cli_main(
        [
            "--anchor",
            ANCHOR_HEX,
            "--ots-proof",
            str(receipt),
            "--output-format",
            "text",
        ]
    )
    out = capsys.readouterr().out
    # The offline pole says what it established about the receipt.
    # Expectation sharpened with R3: "structurally parses" was the
    # whole substance sentence, and structure was the whole check.
    # The sentence now has to name the root binding, because that is
    # what the pole actually did.
    assert "was made for this root" in out
    assert "attests block height(s)" in out
    # The ots-cli pole names the upstream subcommand it ran.
    assert "ots verify -d" in out


# ---------------------------------------------------------------------------
# --save-witnesses (persists alongside text or JSON)
# ---------------------------------------------------------------------------


def test_cli_save_witnesses_persists_verification_json(tmp_path, capsys):
    receipt = _make_receipt(tmp_path)
    out_path = tmp_path / "witness.json"
    rc = cli_main(
        [
            "--anchor",
            ANCHOR_HEX,
            "--ots-proof",
            str(receipt),
            "--save-witnesses",
            str(out_path),
        ]
    )
    assert out_path.exists()
    body = json.loads(out_path.read_text())
    assert body["anchor_hash"] == ANCHOR_HEX
    # Expectation changed with R2/R3: the saved artefact is the full
    # report, so a replaying auditor gets the four claims and not just
    # the pole table. The pole detail is still there, one level down.
    assert body["schema"] == "wakir-verification-report/v1"
    assert [c["claim"] for c in body["claims"]] == [
        "hashlist_consistency",
        "event_binding",
        "payload_check",
        "root_authenticity",
    ]
    assert "pole_results" in body["anchor_verification"]
    assert "quorum" in body["anchor_verification"]


def test_cli_save_witnesses_works_with_text_format(tmp_path, capsys):
    """--save-witnesses always writes JSON regardless of stdout format."""
    receipt = _make_receipt(tmp_path)
    out_path = tmp_path / "witness.json"
    rc = cli_main(
        [
            "--anchor",
            ANCHOR_HEX,
            "--ots-proof",
            str(receipt),
            "--output-format",
            "text",
            "--save-witnesses",
            str(out_path),
        ]
    )
    body = json.loads(out_path.read_text())
    assert body["anchor_hash"] == ANCHOR_HEX
    text_stdout = capsys.readouterr().out
    assert "Conclusion" in text_stdout


# ---------------------------------------------------------------------------
# --capture-witnesses mode
# ---------------------------------------------------------------------------


def test_cli_capture_witnesses_requires_block_height(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli_main(
            [
                "--capture-witnesses",
                "--anchor",
                ANCHOR_HEX,
                "--save-witnesses",
                str(tmp_path / "w.json"),
            ]
        )
    assert excinfo.value.code == 2


def test_cli_capture_witnesses_requires_save_path(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli_main(
            [
                "--capture-witnesses",
                "--anchor",
                ANCHOR_HEX,
                "--block-height",
                "948183",
            ]
        )
    assert excinfo.value.code == 2


def test_cli_capture_witnesses_rejects_bad_anchor(tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli_main(
            [
                "--capture-witnesses",
                "--anchor",
                "not-hex",
                "--block-height",
                "948183",
                "--save-witnesses",
                str(tmp_path / "w.json"),
            ]
        )
    assert excinfo.value.code == 2


def test_cli_text_mode_witness_capture_replay_renders(tmp_path, capsys):
    """A saved witness-capture JSON renders cleanly via the text renderer."""
    # Use the live-capture file the repo ships
    repo_capture = (
        Path(__file__).parent
        / "fixtures"
        / "witness_captures"
        / "2026-05-13-block-948183.json"
    )
    captured = json.loads(repo_capture.read_text())
    from wakir_verify.cli import _render_witness_capture_text

    rendered = _render_witness_capture_text(captured)
    assert "Wakir Audit Trail witness-capture" in rendered
    assert "block height: 948183" in rendered.lower()
    assert "mempool.space" in rendered
    assert "blockstream.info" in rendered
    # Operator-Plattform brand-language
    assert "Operator endpoint" in rendered
