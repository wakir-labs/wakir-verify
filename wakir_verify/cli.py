# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Command-line front-end for the Wakir Audit Trail verifier.

Surface::

    wakir-verify [--anchor <hash>] [--ots-proof <file>]
               [--manifest <file>] [--events <file>] [--proof <file>]
               [--event-id <id>] [--payload <event_id>=<file>]
               [--block-merkle-root <height>=<hex>]
               [--pols all|3-of-4|2-of-4]
               [--expected-block-height <H>] [--expected-block-hash <hex>]
               [--mempool-base-url <url>] [--esplora-base-url <url>]
               [--skip-pole pole_name ...]
               [--output-format json|text]
               [--save-witnesses <path>]

    wakir-verify --capture-witnesses
               --anchor <hash> --block-height <H>
               --save-witnesses <path>
               [--mempool-base-url <url>] [--esplora-base-url <url>]

Four statements, not one word
-----------------------------

The output used to end in a single verdict line, and that line said
``VERIFIED`` on the strength of whichever checks happened to be
available. A reader could not tell which of these had actually
happened, and the weakest of them set the tone for all four:

======================  ====================================================
hash-list consistency   Do the manifest's stored leaf hashes fold to its
                        stored root?
event binding           Do the recorded event fields re-derive those leaf
                        hashes?
payload check           Do supplied payload bytes hash to the committed
                        ``payload_hash``?
root authenticity       Is the root bound into the Bitcoin chain by a
                        complete, root-bound timestamp proof?
======================  ====================================================

Each is reported separately, in both output formats, with its own
``ok`` / ``failed`` / ``not_checked`` status. ``not_checked`` means the
run did not check it — it is never shorthand for "fine". An honestly
disabled time proof is an acceptable outcome; a false positive is not.

Exit codes
----------

* ``0`` — every claim the run made is ``ok``.
* ``1`` — at least one claim ``failed``.
* ``2`` — CLI usage error.
* ``4`` — nothing failed, but at least one claim was ``not_checked``,
  so the positive statement cannot be made. Distinguished from ``1``
  because "I could not check" and "I checked and it is wrong" are
  different messages to an operator; both stay non-zero.

The ``--capture-witnesses`` mode is unchanged: it runs only the two
HTTP poles, records the canonical block hash each observes next to the
anchor, and exits 0 when both answered. It asserts nothing about the
anchor and never did.
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
from wakir_verify.binding import (
    EventInputError,
    check_event_binding,
    check_hashlist_consistency,
    check_payload_binding,
    load_events_from_file,
)
from wakir_verify.claims import (
    CLAIM_EVENT_BINDING,
    CLAIM_HASHLIST,
    CLAIM_ORDER,
    CLAIM_PAYLOAD,
    CLAIM_QUESTIONS,
    CLAIM_ROOT_AUTHENTICITY,
    Claim,
    ClaimSet,
    STATUS_FAILED,
    STATUS_NOT_CHECKED,
    STATUS_OK,
    not_checked,
)
from wakir_verify.manifest import (
    Manifest,
    ManifestParseError,
    load_manifest_from_file,
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
    "pole_python_stdlib": (
        "Pole 1 [mandatory] — offline OTS proof walk (Python stdlib)"
    ),
    "pole_ots_cli": "Pole 2 [mandatory] — upstream `ots verify`",
    "pole_mempool_space": (
        "Pole 3 [supporting] — mempool.space block-header REST"
    ),
    "pole_esplora_blockstream": (
        "Pole 4 [supporting] — blockstream.info Esplora REST"
    ),
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
        required=False,
        default=None,
        help=(
            "Lowercase 64-hex Merkle root anchored by the OTS receipt. "
            "Optional when --manifest is given: the manifest's own root is "
            "used, and a mismatch with an explicit --anchor is an error "
            "rather than a silent preference for one of the two."
        ),
    )
    p.add_argument(
        "--manifest",
        type=str,
        default=None,
        help=(
            "Path to a wakir-wat-manifest/v1 file. Enables the hash-list "
            "consistency and event-binding claims."
        ),
    )
    p.add_argument(
        "--events",
        type=str,
        default=None,
        help=(
            "Path to the event records behind the manifest (JSONL, one "
            "object per line, or a JSON array) carrying at least the four "
            "B1 fields. Binds the manifest to records that did not come "
            "from the manifest. Without it the event-binding claim falls "
            "back to the manifest's own fields and says so."
        ),
    )
    p.add_argument(
        "--proof",
        type=str,
        default=None,
        help=(
            "Path to a wakir-inclusion-proof/v1 artefact. Checked against "
            "this manifest: root, index, leaf hash, event identity and "
            "sibling path."
        ),
    )
    p.add_argument(
        "--event-id",
        type=str,
        default=None,
        help="Event the run is about; must resolve to exactly one leaf.",
    )
    p.add_argument(
        "--payload",
        action="append",
        default=[],
        metavar="EVENT_ID=PATH",
        help=(
            "Payload bytes for an event, as the JSON data slot. Repeatable. "
            "Hashed per SHA-256(JCS(data)) and compared against the leaf's "
            "payload_hash. Without this the payload claim stays not_checked: "
            "a digest does not carry its preimage."
        ),
    )
    p.add_argument(
        "--block-merkle-root",
        action="append",
        default=[],
        metavar="HEIGHT=HEX",
        help=(
            "Merkle root of the Bitcoin block at HEIGHT, in explorer "
            "display order, from a node or an operator's records. "
            "Repeatable. This is what turns the offline pole's Bitcoin "
            "claim into a check; without it that pole reports not_checked "
            "and prints the claim for manual verification."
        ),
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
            "(human-readable, brand-demo and reviewer-readable)."
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


#: Exit code when nothing failed but something went unchecked.
EXIT_NOT_CHECKED = 4


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.capture_witnesses:
        if not args.anchor:
            parser.error("--capture-witnesses requires --anchor")
        return _run_capture_witnesses(args, parser)

    if not args.manifest and not args.ots_proof:
        parser.error(
            "nothing to check: supply --manifest, --ots-proof, or both"
        )

    manifest = _load_manifest_or_exit(args, parser)
    anchor = _resolve_anchor(args, manifest, parser)

    claims: list[Claim] = []
    claims.extend(_manifest_claims(args, manifest, parser))

    verification: AnchorVerification | None = None
    if args.ots_proof:
        verification = _run_anchor_poles(args, anchor, parser)
        claims.append(_root_authenticity_claim(verification))
    else:
        claims.append(
            not_checked(
                CLAIM_ROOT_AUTHENTICITY,
                "no OTS receipt supplied, so the root was not traced to "
                "Bitcoin at all",
            )
        )

    claim_set = ClaimSet.from_iterable(claims)
    report = _build_report(anchor, claim_set, verification)

    if args.save_witnesses:
        _save_witnesses(args.save_witnesses, report)

    if args.output_format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_report_text(report, verification))

    return _exit_code(claim_set)


def _exit_code(claim_set: ClaimSet) -> int:
    status = claim_set.overall_status
    if status == "verified":
        return 0
    if status == STATUS_FAILED:
        return 1
    return EXIT_NOT_CHECKED


def _build_report(
    anchor: str,
    claim_set: ClaimSet,
    verification: AnchorVerification | None,
) -> dict[str, Any]:
    """Assemble the machine-readable report.

    The four claims are the top-level content. The pole detail sits
    underneath ``anchor_verification`` as evidence for exactly one of
    them, which is the relationship the old flat output obscured.
    """
    return {
        "schema": "wakir-verification-report/v1",
        "anchor_hash": anchor,
        "overall_status": claim_set.overall_status,
        "claims": [c.to_dict() for c in claim_set.claims],
        "anchor_verification": (
            verification.to_dict() if verification is not None else None
        ),
    }


def _load_manifest_or_exit(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> Manifest | None:
    if not args.manifest:
        return None
    try:
        return load_manifest_from_file(args.manifest)
    except ManifestParseError as exc:
        parser.error(f"--manifest could not be read: {exc}")
        return None


def _resolve_anchor(
    args: argparse.Namespace,
    manifest: Manifest | None,
    parser: argparse.ArgumentParser,
) -> str:
    """Settle on one anchor hash, refusing to guess between two."""
    manifest_root = manifest.merkle_root.hex() if manifest is not None else None
    if args.anchor and manifest_root and args.anchor.lower() != manifest_root:
        parser.error(
            f"--anchor {args.anchor} is not the manifest's root "
            f"{manifest_root}; refusing to pick one"
        )
    anchor = (args.anchor or manifest_root or "").lower()
    if not anchor:
        parser.error("--anchor is required when --manifest is not given")
    if not _is_hex_anchor(anchor):
        parser.error(
            f"anchor must be 64-char lowercase hex, got {anchor!r}"
        )
    return anchor


def _manifest_claims(
    args: argparse.Namespace,
    manifest: Manifest | None,
    parser: argparse.ArgumentParser,
) -> list[Claim]:
    """The three manifest-side claims, or their not_checked stand-ins."""
    if manifest is None:
        reason = "no manifest supplied"
        return [
            not_checked(CLAIM_HASHLIST, f"{reason}, so no hash list was folded"),
            not_checked(
                CLAIM_EVENT_BINDING,
                f"{reason}, so no leaf hash was recomputed from event fields",
            ),
            not_checked(CLAIM_PAYLOAD, f"{reason}, so no payload was checked"),
        ]

    events = None
    if args.events:
        try:
            events = load_events_from_file(args.events)
        except EventInputError as exc:
            parser.error(str(exc))

    proof = None
    if args.proof:
        try:
            proof = json.loads(Path(args.proof).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"--proof could not be read: {exc}")

    payloads = _parse_payload_args(args.payload, parser)

    return [
        check_hashlist_consistency(manifest),
        check_event_binding(
            manifest,
            events=events,
            proof=proof,
            target_event_id=args.event_id,
        ),
        check_payload_binding(manifest, payloads),
    ]


def _parse_payload_args(
    raw: Sequence[str],
    parser: argparse.ArgumentParser,
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for item in raw or []:
        event_id, sep, path = item.partition("=")
        if not sep or not event_id or not path:
            parser.error(
                f"--payload expects EVENT_ID=PATH, got {item!r}"
            )
        try:
            payloads[event_id] = Path(path).read_bytes()
        except OSError as exc:
            parser.error(f"--payload {event_id}: {exc}")
    return payloads


def _parse_block_merkle_roots(
    raw: Sequence[str],
    parser: argparse.ArgumentParser,
) -> dict[int, str]:
    roots: dict[int, str] = {}
    for item in raw or []:
        height, sep, value = item.partition("=")
        if not sep:
            parser.error(
                f"--block-merkle-root expects HEIGHT=HEX, got {item!r}"
            )
        try:
            roots[int(height)] = value.strip().lower()
        except ValueError:
            parser.error(
                f"--block-merkle-root height {height!r} is not an integer"
            )
    return roots


def _run_anchor_poles(
    args: argparse.Namespace,
    anchor: str,
    parser: argparse.ArgumentParser,
) -> AnchorVerification:
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

    block_roots = _parse_block_merkle_roots(args.block_merkle_root, parser)
    if block_roots:
        pole_overrides.setdefault("pole_python_stdlib", {})[
            "block_merkle_roots"
        ] = block_roots

    if args.mempool_base_url:
        pole_overrides.setdefault("pole_mempool_space", {})[
            "base_url"
        ] = args.mempool_base_url
    if args.esplora_base_url:
        pole_overrides.setdefault("pole_esplora_blockstream", {})[
            "base_url"
        ] = args.esplora_base_url

    enabled = [
        name for name in _POLE_ORDER if name not in (args.skip_pole or [])
    ]
    if not enabled:
        parser.error("--skip-pole removed every pole; nothing to verify.")

    # The HTTP poles need a height to query. Without one they would all
    # report unavailable; trimming them keeps the evidence readable.
    # It does not loosen the verdict: they are supporting poles, and a
    # positive verdict needs a mandatory one either way.
    if args.expected_block_height is None:
        enabled = [
            n
            for n in enabled
            if n not in ("pole_mempool_space", "pole_esplora_blockstream")
        ]

    try:
        return verify_wat_anchor(
            anchor_hash=anchor,
            ots_proof_path=args.ots_proof,
            quorum_policy=QuorumPolicy(args.pols),
            enabled_poles=enabled,
            pole_overrides=pole_overrides,
        )
    except ValueError as exc:
        parser.error(str(exc))
        raise  # unreachable; parser.error exits


def _root_authenticity_claim(verification: AnchorVerification) -> Claim:
    """Translate the pole run into the one claim it speaks to.

    The claim asks whether a complete, root-bound timestamp proof puts
    this root in the Bitcoin chain. That is answered by the mandatory
    poles: either one of them walked the proof and tied the root to an
    attestation, or none did. The supporting quorum is corroboration
    of a different question — what independent operators observe about
    a block — and it is reported as evidence here rather than folded
    into the answer. Folding weaker questions into a stronger one's
    answer is the shape of the defect this branch fixes; doing it in
    the other direction would be the same mistake with better
    manners.

    ``AnchorVerification.quorum`` keeps requiring both, so a library
    caller reading that field gets the stricter of the two readings.
    """
    failed = [
        name
        for name, pr in verification.pole_results.items()
        if pr.verdict == "failed"
    ]

    if failed:
        status = STATUS_FAILED
        summary = (
            "the root is not authenticated by this receipt: "
            + "; ".join(
                verification.pole_results[name].note or name for name in failed
            )
        )
    elif verification.mandatory_verified_by:
        status = STATUS_OK
        summary = (
            "a root-bound timestamp verification ties this root to Bitcoin "
            f"({', '.join(verification.mandatory_verified_by)})"
        )
        if not verification.supporting_quorum:
            summary += (
                "; the supporting block observations did not reach the "
                f"{verification.quorum_policy.value} threshold, so this rests "
                "on the mandatory check alone"
            )
    else:
        status = STATUS_NOT_CHECKED
        summary = (
            "no pole performed a root-bound Bitcoin verification; block "
            "observations and structural checks cannot stand in for one"
        )

    return Claim(
        name=CLAIM_ROOT_AUTHENTICITY,
        status=status,
        summary=summary,
        evidence={
            "quorum_policy": verification.quorum_policy.value,
            "mandatory_verified_by": list(verification.mandatory_verified_by),
            "supporting_quorum": verification.supporting_quorum,
            "aggregate_quorum": verification.quorum,
            "pole_verdicts": {
                name: pr.verdict
                for name, pr in verification.pole_results.items()
            },
        },
    )


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
        binding = witness.get("binding") or {}
        heights = witness.get("heights") or []
        if binding:
            bound = binding.get("bound")
            sentences.append(
                "      Receipt "
                + (
                    f"was made for this root (via {binding.get('mode')})"
                    if bound
                    else "was NOT made for this root"
                )
                + (
                    f" and attests block height(s) {heights}."
                    if heights
                    else " and attests no Bitcoin block."
                )
            )
            for claim in witness.get("bitcoin_claims") or []:
                sentences.append(
                    f"      Claims block {claim['height']} has merkleroot "
                    f"{claim['claimed_block_merkle_root']}."
                )
        elif witness.get("reader") == "injected":
            sentences.append(
                f"      Injected proof reader returned root "
                f"{witness.get('merkle_root_hex')} and height(s) {heights}."
            )
        else:
            sentences.append(
                "      Receipt could not be walked; no anchor statement is "
                "available from this pole."
            )
    elif pr.name == "pole_ots_cli":
        heights = witness.get("heights") or []
        rc = witness.get("returncode")
        mode = witness.get("mode", "verify")
        if mode == "info":
            sentences.append(
                f"      Upstream `ots info` printed height(s) {heights} "
                f"(returncode {rc}); `info` displays, it does not verify."
            )
        else:
            sentences.append(
                f"      Upstream `ots verify -d` exited {rc}"
                + (f", naming height(s) {heights}." if heights else ".")
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


#: Human-readable headings for the four claims, in CLAIM_ORDER.
_CLAIM_LABELS = {
    CLAIM_HASHLIST: "1. Hash-list consistency",
    CLAIM_EVENT_BINDING: "2. Event binding",
    CLAIM_PAYLOAD: "3. Payload check",
    CLAIM_ROOT_AUTHENTICITY: "4. Root authenticity (Bitcoin)",
}

#: Status markers. ASCII on purpose: this output is read in CI logs and
#: in terminals without glyph fonts.
_STATUS_MARK = {
    STATUS_OK: "+",
    STATUS_FAILED: "-",
    STATUS_NOT_CHECKED: "?",
}

_STATUS_WORD = {
    STATUS_OK: "checked, holds",
    STATUS_FAILED: "checked, does NOT hold",
    STATUS_NOT_CHECKED: "NOT CHECKED",
}


def _render_report_text(
    report: Mapping[str, Any],
    verification: AnchorVerification | None,
) -> str:
    """Render the four claims, then the pole evidence, then the verdict.

    Order is the argument: the claims come first because they are what
    the reader is entitled to conclude, and the pole table comes second
    because it is evidence for one of them. The previous layout put the
    pole table first and a single verdict line last, which is how four
    unrelated observations came to read as one endorsement.
    """
    lines: list[str] = []
    lines.append(
        f"Wakir Audit Trail verification — {report['anchor_hash']}"
    )
    lines.append("")
    lines.append("What was checked:")
    lines.append("")

    claims = {c["claim"]: c for c in report["claims"]}
    for name in CLAIM_ORDER:
        claim = claims.get(name)
        if claim is None:
            continue
        mark = _STATUS_MARK.get(claim["status"], "?")
        label = _CLAIM_LABELS.get(name, name)
        word = _STATUS_WORD.get(claim["status"], claim["status"])
        lines.append(f"  [{mark}] {label}: {word}.")
        lines.append(f"      Question: {CLAIM_QUESTIONS.get(name, '')}")
        lines.append(f"      {claim['summary']}")
        lines.append("")

    if verification is not None:
        lines.append("Anchor evidence, pole by pole:")
        lines.append("")
        for name in _POLE_ORDER:
            pr = verification.pole_results.get(name)
            if pr is None:
                continue
            lines.append(_render_pole_text(pr))
            lines.append("")

    lines.append(_render_conclusion(report))
    return "\n".join(lines).rstrip() + "\n"


def _render_conclusion(report: Mapping[str, Any]) -> str:
    """Closing block: the verdict, and what it does not mean."""
    status = report["overall_status"]
    unchecked = [
        _CLAIM_LABELS.get(c["claim"], c["claim"])
        for c in report["claims"]
        if c["status"] == STATUS_NOT_CHECKED
    ]
    failed = [
        _CLAIM_LABELS.get(c["claim"], c["claim"])
        for c in report["claims"]
        if c["status"] == STATUS_FAILED
    ]

    head = "Conclusion"
    lines = [head, "-" * len(head)]
    if status == "verified":
        lines.append(
            "  VERIFIED. All four statements were checked and all four hold."
        )
    elif status == STATUS_FAILED:
        lines.append(
            "  AUDIT FAILURE. Checked and contradicted: " + ", ".join(failed) + "."
        )
        if unchecked:
            lines.append("  Also not checked: " + ", ".join(unchecked) + ".")
    else:
        lines.append(
            "  NOT VERIFIED. Nothing was contradicted, but the following "
            "were not checked, so the positive statement cannot be made: "
            + ", ".join(unchecked)
            + "."
        )
        lines.append(
            "  This is not a failure report. It is the verifier declining "
            "to assert what it did not establish."
        )
    lines.append(
        "  Replay contract: a third-party auditor can rerun this verifier "
        "with the same manifest, event records and .ots receipt and "
        "reproduce this report without operating any Wakir-controlled "
        "software."
    )
    return "\n".join(lines)


def _render_quorum_conclusion(verification: AnchorVerification) -> str:
    """Pole-level summary, retained for :func:`_render_verification_text`.

    Reports the two conditions separately — a mandatory root-bound
    verdict and the supporting threshold — because collapsing them into
    one count is what produced the false positive.
    """
    pole_results = verification.pole_results
    total = len(pole_results)
    ok_count = sum(1 for pr in pole_results.values() if pr.ok)
    unavailable = sum(
        1 for pr in pole_results.values() if pr.verdict == "unavailable"
    )
    failed = sum(1 for pr in pole_results.values() if pr.verdict == "failed")

    threshold_text = {
        QuorumPolicy.THREE_OF_FOUR: "3 of 4 poles must report ok",
        QuorumPolicy.ALL: "all configured poles must report ok",
        QuorumPolicy.TWO_OF_FOUR: "2 of 4 poles must report ok (debug-only)",
    }.get(verification.quorum_policy, "(unknown threshold)")

    head = "Anchor conclusion"
    lines = [head, "-" * len(head)]
    if verification.mandatory_verified_by:
        lines.append(
            "  Mandatory root-bound verification: satisfied by "
            + ", ".join(verification.mandatory_verified_by)
            + "."
        )
    else:
        lines.append(
            "  Mandatory root-bound verification: NOT satisfied. No pole "
            "tied this root to a Bitcoin attestation."
        )
    lines.append(
        f"  Supporting evidence: {ok_count}/{total} poles ok, {failed} failed, "
        f"{unavailable} unavailable; threshold: {threshold_text}."
    )
    verdict_word = {
        "verified": "VERIFIED",
        "failed": "AUDIT FAILURE",
        "not_checked": "NOT CHECKED",
    }.get(verification.overall_status, verification.overall_status.upper())
    lines.append(f"  Verdict: {verdict_word}.")
    return "\n".join(lines)


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
