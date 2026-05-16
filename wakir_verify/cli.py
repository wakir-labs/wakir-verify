# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Command-line front-end for the 4-pole external verifier.

Surface:

    wakir-verify --anchor <hash> --ots-proof <file>
               [--pols all|3-of-4|2-of-4]
               [--expected-block-height <H>]
               [--expected-block-hash <hex>]
               [--mempool-base-url <url>] [--esplora-base-url <url>]
               [--skip-pole pole_name ...]
               [--output-format json|text]
               [--save-witnesses <path>]

    wakir-verify --capture-witnesses
               --anchor <hash>
               --block-height <H>
               --save-witnesses <path>
               [--mempool-base-url <url>] [--esplora-base-url <url>]

Output: JSON (default) or human-readable text to stdout. Exit codes:

* 0 — quorum reached (or witness-capture run completed).
* 1 — quorum not reached (audit-failure verdict).
* 2 — CLI usage error.

The default ``--output-format`` is JSON because the original Tag-1
audit contract was JSON-pipeable to ``jq``; the text mode is for
brand-demo and Aufsichtsrat-readable verification reports and uses
the Operator-Plattform wording from ADR-0055.

The ``--capture-witnesses`` mode is the brand-proof witness-capture
seam: it runs only the two HTTP poles, in witness-capture mode
(no expected_block_hash assertion), and saves the observed canonical
block hash from each pole next to the anchor for later replay. The
saved JSON is the asset operators ship to third-party auditors when
the verification needs to be redone offline without re-touching the
public Esplora APIs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from wakir_verify.aggregator import (
    AnchorVerification,
    QuorumPolicy,
    verify_wat_anchor,
)
from wakir_verify.poles import (
    ESPLORA_BLOCKSTREAM_BASE_URL,
    MEMPOOL_SPACE_BASE_URL,
    pole_esplora_blockstream_verify,
    pole_mempool_space_verify,
)
from wakir_verify.types import PoleResult


# Ordered list of pole names rendered in CLI output. The order is the
# canonical pole order, matching the registry; we re-state it here to
# make the rendering surface stable independent of registry ordering.
_POLE_ORDER = (
    "pole_python_stdlib",
    "pole_ots_cli",
    "pole_mempool_space",
    "pole_esplora_blockstream",
)


# Human-readable labels for the text renderer. Keeps the brand-demo
# output legible without the operator having to know the internal
# pole_name slugs.
_POLE_LABELS = {
    "pole_python_stdlib": "Pole 1 — offline OTS-receipt parser (Python stdlib)",
    "pole_ots_cli": "Pole 2 — upstream OpenTimestamps CLI",
    "pole_mempool_space": "Pole 3 — mempool.space block-header REST",
    "pole_esplora_blockstream": "Pole 4 — blockstream.info Esplora REST",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wakir-verify",
        description=(
            "4-pole cross-library verifier for Wakir Audit Trail "
            "Bitcoin anchors. Runs an OTS proof file through four "
            "independent verifier poles and emits a quorum verdict. "
            "Built for operator-plattform third-party audit, not for "
            "consumer-app verification."
        ),
    )
    p.add_argument(
        "--anchor",
        required=True,
        help="Lowercase 64-hex Merkle root anchored by the OTS receipt.",
    )
    p.add_argument(
        "--ots-proof",
        required=False,
        default=None,
        help=(
            "Path to the .ots receipt file. Required for the default "
            "verify mode; not needed for --capture-witnesses."
        ),
    )
    p.add_argument(
        "--pols",
        choices=[pol.value for pol in QuorumPolicy],
        default=QuorumPolicy.THREE_OF_FOUR.value,
        help="Quorum policy (default: 3-of-4).",
    )
    p.add_argument(
        "--expected-block-height",
        type=int,
        default=None,
        help=(
            "Bitcoin block height the receipt is expected to attest. "
            "Required for the two HTTP poles; without it those poles "
            "return 'unavailable' and the quorum falls back to the "
            "offline poles."
        ),
    )
    p.add_argument(
        "--expected-block-hash",
        type=str,
        default=None,
        help=(
            "Optional canonical block hash to assert against the "
            "HTTP-pole responses. When omitted, the HTTP poles run "
            "in witness-capture mode."
        ),
    )
    p.add_argument(
        "--mempool-base-url",
        type=str,
        default=None,
        help="Override base URL for the mempool.space pole.",
    )
    p.add_argument(
        "--esplora-base-url",
        type=str,
        default=None,
        help="Override base URL for the blockstream.info pole.",
    )
    p.add_argument(
        "--skip-pole",
        action="append",
        default=[],
        help=(
            "Disable a pole by name. Repeatable. Useful for "
            "operator-host-only verification (e.g. skip both HTTP "
            "poles for an offline brand-proof rerun)."
        ),
    )
    p.add_argument(
        "--output-format",
        choices=("json", "text"),
        default="json",
        help=(
            "json (default, audit-pipeable) or text "
            "(human-readable, brand-demo and Aufsichtsrat-friendly)."
        ),
    )
    p.add_argument(
        "--save-witnesses",
        type=str,
        default=None,
        help=(
            "Persist the verification result as JSON to the given "
            "path. The saved structure matches AnchorVerification."
            "to_dict() and is replayable by third-party auditors."
        ),
    )
    p.add_argument(
        "--capture-witnesses",
        action="store_true",
        help=(
            "Witness-capture mode: skip OTS-receipt parsing entirely "
            "and run only the two HTTP poles against the given block "
            "height to record the canonical block hash they observe. "
            "Requires --anchor, --block-height, and --save-witnesses."
        ),
    )
    p.add_argument(
        "--block-height",
        type=int,
        default=None,
        help=(
            "Bitcoin block height to query in --capture-witnesses "
            "mode. Ignored outside witness-capture mode "
            "(--expected-block-height is the equivalent there)."
        ),
    )
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.capture_witnesses:
        return _run_capture_witnesses(args, parser)

    if not args.ots_proof:
        parser.error("--ots-proof is required (except in --capture-witnesses mode)")
        return 2

    pole_overrides: dict[str, dict] = {}
    if args.expected_block_height is not None:
        for pole_name in ("pole_mempool_space", "pole_esplora_blockstream"):
            pole_overrides[pole_name] = {
                "expected_block_height": args.expected_block_height,
                "expected_block_hash": args.expected_block_hash,
            }
        pole_overrides["pole_python_stdlib"] = {
            "expected_block_height": args.expected_block_height,
        }
        pole_overrides["pole_ots_cli"] = {
            "expected_block_height": args.expected_block_height,
        }

    if args.mempool_base_url:
        pole_overrides.setdefault("pole_mempool_space", {})[
            "base_url"
        ] = args.mempool_base_url
    if args.esplora_base_url:
        pole_overrides.setdefault("pole_esplora_blockstream", {})[
            "base_url"
        ] = args.esplora_base_url

    enabled = [
        name
        for name in _POLE_ORDER
        if name not in (args.skip_pole or [])
    ]
    if not enabled:
        parser.error("--skip-pole removed every pole; nothing to verify.")

    # If HTTP poles are enabled but the operator did not supply
    # --expected-block-height, the two HTTP poles cannot run at all
    # (they need a height to query). Trim them rather than letting
    # them fail-unavailable; the operator gets a clean offline-only
    # verdict instead of a noisy 2-of-4 fallback.
    if args.expected_block_height is None:
        enabled = [
            n
            for n in enabled
            if n not in ("pole_mempool_space", "pole_esplora_blockstream")
        ]

    try:
        verification = verify_wat_anchor(
            anchor_hash=args.anchor,
            ots_proof_path=args.ots_proof,
            quorum_policy=QuorumPolicy(args.pols),
            enabled_poles=enabled,
            pole_overrides=pole_overrides,
        )
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if args.save_witnesses:
        _save_witnesses(args.save_witnesses, verification.to_dict())

    if args.output_format == "json":
        print(json.dumps(verification.to_dict(), indent=2, sort_keys=True))
    else:
        print(_render_verification_text(verification))

    return 0 if verification.quorum else 1


# ---------------------------------------------------------------------------
# Witness-capture mode
# ---------------------------------------------------------------------------


def _run_capture_witnesses(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> int:
    """Run only the two HTTP poles in witness-capture mode.

    This mode exists for the brand-proof workflow: operators who
    already trust the local OTS-anchor pipeline want a recorded,
    third-party-observable canonical block hash sitting next to the
    anchor in the audit trail. Saving the captured witness JSON
    makes the verification replayable: later auditors compare the
    recorded canonical hash against the live Esplora response of
    the day and any divergence is a tamper signal.
    """
    if args.block_height is None:
        parser.error("--capture-witnesses requires --block-height")
        return 2
    if args.save_witnesses is None:
        parser.error("--capture-witnesses requires --save-witnesses")
        return 2
    if not _is_hex_anchor(args.anchor):
        parser.error(
            f"anchor_hash must be 64-char lowercase hex, got {args.anchor!r}"
        )
        return 2

    base_urls = {
        "pole_mempool_space": args.mempool_base_url or MEMPOOL_SPACE_BASE_URL,
        "pole_esplora_blockstream": args.esplora_base_url
        or ESPLORA_BLOCKSTREAM_BASE_URL,
    }

    pole_results: dict[str, PoleResult] = {}
    pole_results["pole_mempool_space"] = pole_mempool_space_verify(
        anchor_hash=args.anchor,
        ots_proof_path="",  # witness-capture mode ignores receipt
        expected_block_height=args.block_height,
        expected_block_hash=None,
        base_url=base_urls["pole_mempool_space"],
    )
    pole_results["pole_esplora_blockstream"] = pole_esplora_blockstream_verify(
        anchor_hash=args.anchor,
        ots_proof_path="",
        expected_block_height=args.block_height,
        expected_block_hash=None,
        base_url=base_urls["pole_esplora_blockstream"],
    )

    captured = {
        "schema": "wakir-witness-capture/v1",
        "anchor_hash": args.anchor,
        "block_height": args.block_height,
        "mode": "witness-capture",
        "base_urls": base_urls,
        "pole_witnesses": {
            name: pr.to_dict() for name, pr in pole_results.items()
        },
    }

    _save_witnesses(args.save_witnesses, captured)

    if args.output_format == "json":
        print(json.dumps(captured, indent=2, sort_keys=True))
    else:
        print(_render_witness_capture_text(captured))

    # Witness-capture mode exits 0 as long as both poles were
    # reachable and returned a structurally valid block hash. A pole
    # outage is not a CLI failure — the operator can re-run the
    # capture from a different host.
    all_ok = all(pr.ok for pr in pole_results.values())
    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------


def _render_verification_text(verification: AnchorVerification) -> str:
    """Render a 4-pole AnchorVerification as a human-readable block.

    Format contract:
      * 2-3 sentences per pole, prefixed with ``+`` (ok) or ``-`` (not ok).
      * Block-end quorum-conclusion summary with explicit thresholds.
      * Operator-Plattform wording (ADR-0055): "audit trail",
        "operator", "third-party auditor" — no "user", "consumer",
        "app".

    Symbol choice: ``+`` / ``-`` ASCII rather than ``checkmark`` /
    ``cross-mark`` Unicode glyphs. The brand-demo terminal output is
    rendered in monospace fonts on machines that may not have the
    Unicode glyph fonts installed; ASCII is the boring-tech default
    and stays readable in CI logs.
    """
    lines: list[str] = []
    lines.append(
        f"Wakir Audit Trail anchor verification — {verification.anchor_hash}"
    )
    lines.append(f"Quorum policy: {verification.quorum_policy.value}")
    lines.append("")
    lines.append("Per-pole results:")
    lines.append("")

    for name in _POLE_ORDER:
        pr = verification.pole_results.get(name)
        if pr is None:
            continue
        lines.append(_render_pole_text(pr))
        lines.append("")

    lines.append(_render_quorum_conclusion(verification))
    return "\n".join(lines).rstrip() + "\n"


def _render_pole_text(pr: PoleResult) -> str:
    """Format one pole result as 2-3 sentences with a status symbol."""
    label = _POLE_LABELS.get(pr.name, pr.name)
    symbol = "+" if pr.ok else "-"
    verdict_word = pr.verdict
    head = f"  [{symbol}] {label}: {verdict_word}."

    # Substance sentence — what did the pole actually observe?
    witness = pr.witness or {}
    sentences: list[str] = []
    if pr.name == "pole_python_stdlib":
        heights = witness.get("heights") or []
        if heights:
            sentences.append(
                f"      Receipt structurally parses as an OpenTimestamps "
                f"proof and names block height(s) {heights}."
            )
        else:
            sentences.append(
                "      Receipt did not yield any BitcoinBlockHeaderAttestation "
                "lines; pole cannot witness a Bitcoin anchor."
            )
    elif pr.name == "pole_ots_cli":
        heights = witness.get("heights") or []
        rc = witness.get("returncode")
        if heights:
            sentences.append(
                f"      Upstream `ots info` reported block height(s) {heights} "
                f"(returncode {rc})."
            )
        else:
            sentences.append(
                f"      Upstream `ots info` returned no block-height attestation "
                f"(returncode {rc})."
            )
    elif pr.name in ("pole_mempool_space", "pole_esplora_blockstream"):
        observed = witness.get("observed_block_hash")
        height = witness.get("height")
        expected = witness.get("expected_block_hash")
        url = witness.get("url")
        mode = witness.get("mode")
        if observed and expected:
            sentences.append(
                f"      Operator endpoint {url} reports block {height} -> "
                f"{observed}; recorded canonical hash is {expected}."
            )
        elif observed and mode == "witness-capture":
            sentences.append(
                f"      Operator endpoint {url} reports block {height} -> "
                f"{observed} (witness-capture mode; no equality assertion)."
            )
        else:
            status = witness.get("status")
            sentences.append(
                f"      Operator endpoint {url} returned status {status}; "
                "no canonical block hash observed."
            )

    if pr.note:
        sentences.append(f"      Note: {pr.note}")

    return "\n".join([head, *sentences])


def _render_quorum_conclusion(verification: AnchorVerification) -> str:
    pole_results = verification.pole_results
    total = len(pole_results)
    ok_count = sum(1 for pr in pole_results.values() if pr.ok)
    unavailable = sum(
        1 for pr in pole_results.values() if pr.verdict == "unavailable"
    )
    failed = sum(1 for pr in pole_results.values() if pr.verdict == "failed")

    threshold_text = {
        QuorumPolicy.THREE_OF_FOUR: "3 of 4 poles must verify",
        QuorumPolicy.ALL: "all configured poles must verify",
        QuorumPolicy.TWO_OF_FOUR: "2 of 4 poles must verify (debug-only)",
    }.get(verification.quorum_policy, "(unknown threshold)")

    head = "Quorum conclusion"
    underline = "-" * len(head)
    if verification.quorum:
        verdict_line = (
            f"  Verdict: VERIFIED. {ok_count}/{total} poles agreed, threshold: "
            f"{threshold_text}."
        )
    else:
        verdict_line = (
            f"  Verdict: AUDIT FAILURE. {ok_count}/{total} poles verified, "
            f"{failed} failed, {unavailable} unavailable, threshold: "
            f"{threshold_text}."
        )
    advice = (
        "  Replay contract: any third-party auditor can rerun the verifier "
        "with the saved witness JSON and the .ots receipt to reproduce this "
        "verdict without operating any Wakir-controlled software."
    )
    return "\n".join([head, underline, verdict_line, advice])


def _render_witness_capture_text(captured: Mapping[str, Any]) -> str:
    """Render the --capture-witnesses output as readable text."""
    anchor = captured["anchor_hash"]
    height = captured["block_height"]
    pole_witnesses = captured["pole_witnesses"]

    lines: list[str] = []
    lines.append("Wakir Audit Trail witness-capture")
    lines.append(f"Anchor: {anchor}")
    lines.append(f"Bitcoin block height: {height}")
    lines.append("")
    lines.append("HTTP-pole observations:")
    lines.append("")

    for name in ("pole_mempool_space", "pole_esplora_blockstream"):
        pr_dict = pole_witnesses.get(name)
        if pr_dict is None:
            continue
        ok = pr_dict["ok"]
        symbol = "+" if ok else "-"
        label = _POLE_LABELS.get(name, name)
        witness = pr_dict.get("witness", {})
        observed = witness.get("observed_block_hash") or "<no hash observed>"
        url = witness.get("url", "<no url>")
        status = witness.get("status")
        if ok:
            sentence = (
                f"      Operator endpoint {url} returned canonical hash "
                f"{observed} for height {height}."
            )
        else:
            sentence = (
                f"      Operator endpoint {url} did not return a canonical "
                f"hash (status {status}); witness-capture failed for this pole."
            )
        lines.append(f"  [{symbol}] {label}: {pr_dict['verdict']}.")
        lines.append(sentence)
        if pr_dict.get("note"):
            lines.append(f"      Note: {pr_dict['note']}")
        lines.append("")

    lines.append(
        "Recorded witness JSON is replayable: a third-party auditor can"
        " compare the saved canonical hash against the live Esplora response"
        " at any later time to detect tamper or chain-split anomalies."
    )
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _save_witnesses(path: str, payload: Mapping[str, Any]) -> None:
    """Write a verification or witness-capture payload to disk as JSON."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _is_hex_anchor(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
    except ValueError:
        return False
    return s == s.lower()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
