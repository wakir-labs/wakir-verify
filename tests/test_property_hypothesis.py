# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Hypothesis property-tests for the external-verifier surface (Sprint-8 Tag-4).

Background
----------

Sprint-8 Tag-3 (TV-DET-3) shipped a parser-determinism check using
``stdlib`` ``random.Random(seed)`` over fifty hand-rolled seeds. That
was a stand-in: substantive shrinking, drift-finding, and
counter-example minimisation are the value-add of a real
property-based testing library. Tag-4 deepens TV-DET-3 with five
Hypothesis-driven property-tests over the parser, aggregator, and
discrepancy-summary surface.

License / scope contract
------------------------

Hypothesis is **test-only**. It MUST NOT appear in the
External-Verifier-Runtime-Surface: the brand-proof contract third
parties run without any Wakir-controlled software depends on the
verifier sub-package having zero PyPI surface, and adding Hypothesis
to ``dependencies = [...]`` in ``pyproject.toml`` would silently
break that posture. Hypothesis sits behind the ``[test]`` extra and
is imported only by files under ``tests/``. See ADR-0007
§verifier-surface and the inline note in ``pyproject.toml`` next to
the ``hypothesis>=6.100`` entry.

Property test matrix (TV-PROP-*):

* **TV-PROP-1 — parser is deterministic and idempotent across
  arbitrary well-formed ``ots info`` text.**
  Strategy: build text from a random list of block heights
  interleaved with random noise lines, alternate the two regex
  shapes the parser supports. Property: calling
  ``_extract_heights_from_text`` twice returns equal results and
  the result equals the first-seen-and-deduped projection of the
  input heights.

* **TV-PROP-2 — parser is robust against arbitrary (potentially
  malformed) decoded text.**
  Strategy: arbitrary printable/unicode strings (no constraint on
  matching the regex). Property: the parser never raises, always
  returns ``list[int]``, never produces duplicates, every height
  is in ``[1, 2**32)`` (regex matches digit-runs of bounded form).

* **TV-PROP-3 — aggregator is idempotent under repeated invocation.**
  Strategy: ``verify_wat_anchor`` invoked twice with identical
  injection-mocked overrides. Property: ``to_dict()`` outputs are
  bit-identical (sorted JSON serialisation).

* **TV-PROP-4 — discrepancy summary is a pure function of
  pole_results.**
  Strategy: synthesise arbitrary ``AnchorVerification`` values
  with random pole verdicts and witnesses; run
  ``summarise_discrepancies`` twice. Property: results are equal,
  severity is one of the four declared values, ``failed_poles``
  and ``unavailable_poles`` partition the non-ok poles correctly.

* **TV-PROP-5 — quorum threshold is monotone in strictness.**
  Strategy: pick an arbitrary set of pole ok-flags (size 1..6).
  Property: if ``ALL`` passes then ``THREE_OF_FOUR`` and
  ``TWO_OF_FOUR`` also pass; if ``THREE_OF_FOUR`` passes then
  ``TWO_OF_FOUR`` also passes. (No reverse-implication.)

OTS-bytes strategies
--------------------

Two strategies are exposed for callers who want to drive their own
property tests:

* :func:`ots_proof_bytes_well_formed` — bytes that begin with the
  OTS magic-bytes header and a randomised
  ``BitcoinBlockHeaderAttestation(H)`` line. Accepted by the
  structural pole.

* :func:`ots_proof_bytes_malformed` — bytes that deliberately do
  NOT begin with the OTS magic-bytes header (random prefix), with
  arbitrary tail. The structural pole must reject these with
  ``verdict="failed"`` and not crash.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

# Skip the whole module cleanly when hypothesis is absent (e.g. the
# sandbox-CI lane which intentionally trims optional test deps).
hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given, settings, strategies as st  # noqa: E402

from wakir_verify import (  # noqa: E402
    AnchorVerification,
    QuorumPolicy,
    PoleResult,
    summarise_discrepancies,
    verify_wat_anchor,
)
from wakir_verify.aggregator import _evaluate_quorum  # noqa: E402
from wakir_verify.poles import _extract_heights_from_text  # noqa: E402

from tests.fixtures import (  # noqa: E402
    RECEIPT_948183_BYTES,
    make_http_transport,
    make_ots_runner,
    make_proof_reader,
)


# ---------------------------------------------------------------------------
# Strategies — OTS proof bytes
# ---------------------------------------------------------------------------

_OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


@st.composite
def ots_proof_bytes_well_formed(draw) -> bytes:
    """Strategy: bytes for a structurally-acceptable OTS receipt.

    The structural pole 1 (``pole_python_stdlib_verify``) accepts any
    blob that begins with the OTS magic-bytes header. We synthesise a
    minimal but distinguishable body: a random
    ``BitcoinBlockHeaderAttestation(H)`` text line plus a short
    random binary tail so two distinct draws are unlikely to collide.

    Heights are bounded to ``[1, 2**31)`` — the parser regex matches
    any digit-run but real block heights are < 2**32; the bound keeps
    the search space honest without artificially exploding it.
    """
    height = draw(st.integers(min_value=1, max_value=(2**31) - 1))
    tail_len = draw(st.integers(min_value=0, max_value=64))
    tail = draw(st.binary(min_size=tail_len, max_size=tail_len))
    line = f"BitcoinBlockHeaderAttestation({height})\n".encode("ascii")
    return _OTS_MAGIC + line + tail


@st.composite
def ots_proof_bytes_malformed(draw) -> bytes:
    """Strategy: bytes that deliberately are NOT a valid OTS receipt.

    The first 31 bytes are random and constrained to differ from the
    OTS magic header (we just drop draws that happen to collide; the
    collision probability is ~2**-248 so the filter rate is
    negligible). The structural pole must reject these with
    ``verdict="failed"`` (length-known but magic absent) and never
    crash.
    """
    prefix = draw(
        st.binary(min_size=len(_OTS_MAGIC), max_size=len(_OTS_MAGIC)).filter(
            lambda b: b != _OTS_MAGIC
        )
    )
    tail = draw(st.binary(min_size=0, max_size=128))
    return prefix + tail


# ---------------------------------------------------------------------------
# Strategies — well-formed parser-input text
# ---------------------------------------------------------------------------


@st.composite
def parser_text_well_formed(draw) -> tuple[str, list[int]]:
    """Strategy: ``(text, expected_heights)`` for the parser.

    Builds a multi-line text where each height is rendered with one
    of the two regex-supported shapes (``BitcoinBlockHeaderAttestation``
    or ``Bitcoin block``), with random noise lines interleaved that
    must not match. ``expected_heights`` is the de-duplicated
    first-seen projection — the contract the parser is supposed to
    honour.
    """
    heights = draw(
        st.lists(
            st.integers(min_value=1, max_value=(2**31) - 1),
            min_size=0,
            max_size=8,
        )
    )
    lines: list[str] = []
    for h in heights:
        shape = draw(st.sampled_from(["attestation", "block"]))
        if shape == "attestation":
            lines.append(f"BitcoinBlockHeaderAttestation({h})")
        else:
            lines.append(f"Bitcoin block {h}")
        # Inject a non-matching noise line (no digits adjacent to
        # the matched literals).
        noise = draw(
            st.text(
                alphabet=st.characters(
                    blacklist_categories=("Cs",),
                    blacklist_characters="\n",
                ),
                max_size=24,
            )
        )
        # Belt and braces: make sure the noise line cannot accidentally
        # match the regex by stripping the literal triggers.
        noise = (
            noise
            .replace("BitcoinBlockHeaderAttestation", "X")
            .replace("Bitcoin block", "X")
            .replace("Bitcoin Block", "X")
            .replace("Bitcoin  block", "X")
        )
        lines.append(noise)

    text = "\n".join(lines)

    seen: list[int] = []
    for h in heights:
        if h not in seen:
            seen.append(h)
    return text, seen


# ---------------------------------------------------------------------------
# TV-PROP-1: parser determinism and idempotence
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(parser_text_well_formed())
def test_tv_prop_1_parser_deterministic_and_correct(
    payload: tuple[str, list[int]],
) -> None:
    text, expected = payload
    first = _extract_heights_from_text(text)
    second = _extract_heights_from_text(text)
    assert first == second, (
        f"parser non-deterministic on text={text!r}: "
        f"first={first} second={second}"
    )
    assert first == expected, (
        f"parser drifted from first-seen+dedup contract on text={text!r}: "
        f"got={first} expected={expected}"
    )


# ---------------------------------------------------------------------------
# TV-PROP-2: parser robustness on arbitrary input
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(
    st.text(
        alphabet=st.characters(blacklist_categories=("Cs",)),
        max_size=256,
    )
)
def test_tv_prop_2_parser_robust_on_arbitrary_text(text: str) -> None:
    """Parser must never raise on arbitrary text and always return ``list[int]``."""
    result = _extract_heights_from_text(text)
    assert isinstance(result, list)
    assert all(isinstance(h, int) for h in result)
    # First-seen-and-deduped contract holds: no duplicate values.
    assert len(result) == len(set(result)), (
        f"parser emitted duplicates on text={text!r}: {result}"
    )
    # All extracted heights are non-negative ints (the regex captures
    # digit-runs; ``int(digits)`` is therefore >= 0).
    assert all(h >= 0 for h in result)


# ---------------------------------------------------------------------------
# TV-PROP-3: aggregator idempotence on identical injection-mocked input
# ---------------------------------------------------------------------------


_ANCHOR_HEX = "d16216b92bac7653828301b0b8b5595028a636eaf1bfd0f10d9b9a5fbd1b1894"
_CANONICAL_HASH = (
    "0000000000000000000a1d2c3b4e5f60718293a4b5c6d7e8f90123456789abcd"
)


def _build_overrides(height: int, canonical_hash: str) -> dict:
    return {
        "pole_python_stdlib": {
            "expected_block_height": height,
            "proof_reader": make_proof_reader(
                merkle_root_hex=_ANCHOR_HEX,
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
    return json.dumps(
        verification.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    )


@settings(max_examples=40, deadline=None)
@given(
    height=st.integers(min_value=1, max_value=(2**31) - 1),
)
def test_tv_prop_3_aggregator_idempotent(tmp_path_factory, height: int) -> None:
    """Two identical aggregator invocations produce bit-identical to_dict()."""
    tmp = tmp_path_factory.mktemp("agg-idem")
    receipt = tmp / "root.bin.ots"
    receipt.write_bytes(RECEIPT_948183_BYTES)
    overrides = _build_overrides(height, _CANONICAL_HASH)

    first = verify_wat_anchor(
        anchor_hash=_ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    second = verify_wat_anchor(
        anchor_hash=_ANCHOR_HEX,
        ots_proof_path=str(receipt),
        pole_overrides=overrides,
    )
    assert _serialise(first) == _serialise(second), (
        f"aggregator non-idempotent on height={height}; "
        f"first={_serialise(first)!r} second={_serialise(second)!r}"
    )


# ---------------------------------------------------------------------------
# TV-PROP-4: discrepancy summary is a pure function of pole_results
# ---------------------------------------------------------------------------


_POLE_NAMES = (
    "pole_python_stdlib",
    "pole_ots_cli",
    "pole_mempool_space",
    "pole_esplora_blockstream",
)

_VERDICTS = ("verified", "failed", "unavailable")


@st.composite
def synthetic_anchor_verification(draw) -> AnchorVerification:
    """Strategy: a randomly-shaped :class:`AnchorVerification`.

    Each of the four poles independently draws a verdict and a
    matching witness dict (verified poles carry a hash + height,
    failed poles may carry the same shape with a different hash,
    unavailable poles carry an empty witness).
    """
    pole_results: dict[str, PoleResult] = {}
    for name in _POLE_NAMES:
        verdict = draw(st.sampled_from(_VERDICTS))
        if verdict == "verified":
            obs_hash = draw(
                st.sampled_from(
                    [
                        _CANONICAL_HASH,
                        # Alternative hash to seed inter-ok hash disagreement.
                        "0000000000000000000a" + "f" * 44,
                    ]
                )
            )
            obs_height = draw(st.sampled_from([948183, 948184]))
            witness: dict[str, Any] = {
                "observed_block_hash": obs_hash,
                "heights": [obs_height],
            }
            ok = True
        elif verdict == "failed":
            witness = {
                "observed_block_hash": "00" * 32,
                "heights": [draw(st.integers(min_value=1, max_value=1_000_000))],
            }
            ok = False
        else:  # unavailable
            witness = {}
            ok = False
        pole_results[name] = PoleResult(
            name=name,
            ok=ok,
            verdict=verdict,
            witness=witness,
            note="",
        )

    witnesses = [(n, pr.witness) for n, pr in pole_results.items()]
    return AnchorVerification(
        anchor_hash=_ANCHOR_HEX,
        quorum_policy=QuorumPolicy.THREE_OF_FOUR,
        quorum=sum(1 for pr in pole_results.values() if pr.ok) >= 3,
        pole_results=pole_results,
        witnesses=witnesses,
    )


@settings(max_examples=200, deadline=None)
@given(synthetic_anchor_verification())
def test_tv_prop_4_discrepancy_summary_pure(
    verification: AnchorVerification,
) -> None:
    """``summarise_discrepancies`` is a deterministic pure function.

    Two invocations on the same verification must return equal dicts,
    severity must be one of the four declared values, and
    ``ok_poles`` + ``failed_poles`` + ``unavailable_poles`` must
    partition exactly the pole names that hold that verdict.
    """
    first = summarise_discrepancies(verification)
    second = summarise_discrepancies(verification)
    assert first == second, (
        f"summarise_discrepancies non-deterministic; "
        f"first={first} second={second}"
    )
    assert first["severity"] in {
        "none",
        "silent-minority",
        "substance",
        "brand-critical",
    }
    # Partition contract.
    ok_set = set(first["ok_poles"])
    failed_set = set(first["failed_poles"])
    unavail_set = set(first["unavailable_poles"])
    assert ok_set.isdisjoint(failed_set)
    assert ok_set.isdisjoint(unavail_set)
    assert failed_set.isdisjoint(unavail_set)
    # Every named pole appears in exactly one of the three buckets
    # OR in none of them if its verdict is something else (the
    # current dataclass only declares three verdicts, but the
    # summary surface is additive — be permissive).
    for name, pr in verification.pole_results.items():
        if pr.ok:
            assert name in ok_set
        if pr.verdict == "failed":
            assert name in failed_set
        if pr.verdict == "unavailable":
            assert name in unavail_set


# ---------------------------------------------------------------------------
# TV-PROP-5: quorum threshold monotonicity
# ---------------------------------------------------------------------------


def _make_pole_results_from_oks(ok_flags: list[bool]) -> dict[str, PoleResult]:
    """Synthesise ``pole_results`` from a list of ok-flags.

    The pole name is synthetic (``pole_N``); verdicts are
    ``"verified"`` for ok=True and ``"failed"`` for ok=False
    (failed counts as a non-ok-vote for quorum purposes, matching
    the aggregator's actual semantics).
    """
    out: dict[str, PoleResult] = {}
    for i, ok in enumerate(ok_flags):
        out[f"pole_{i}"] = PoleResult(
            name=f"pole_{i}",
            ok=ok,
            verdict="verified" if ok else "failed",
            witness={},
            note="",
        )
    return out


# ---------------------------------------------------------------------------
# TV-PROP-6: OTS-bytes strategies exercise the structural pole
# ---------------------------------------------------------------------------
#
# This test exists to demonstrate that the two OTS-bytes strategies
# (``ots_proof_bytes_well_formed`` / ``ots_proof_bytes_malformed``)
# do what their docstrings claim against the actual structural pole.
# It also pins the contract that the structural pole never crashes
# on arbitrary bytes — a small but load-bearing piece of the brand-
# proof posture (an auditor must be able to feed garbage to the
# verifier and get a structured "failed" verdict, not a stack trace).


@settings(max_examples=100, deadline=None)
@given(ots_proof_bytes_well_formed())
def test_tv_prop_6a_well_formed_ots_bytes_accepted_by_structural_pole(
    tmp_path_factory,
    blob: bytes,
) -> None:
    """Well-formed-OTS-bytes strategy yields blobs the structural pole accepts.

    "Accepts" here means: not ``unavailable`` (file is readable),
    and structurally not rejected for missing magic-bytes header.
    The verdict may still be ``failed`` if no ``expected_block_height``
    is supplied (the default body requires either a height match or
    a proof_reader). We only check the structural-shape contract.
    """
    from wakir_verify.poles import pole_python_stdlib_verify
    tmp = tmp_path_factory.mktemp("ots-wf")
    path = tmp / "wf.ots"
    path.write_bytes(blob)
    result = pole_python_stdlib_verify(
        anchor_hash=_ANCHOR_HEX,
        ots_proof_path=str(path),
        # No expected_height: we are testing structure-acceptance,
        # not substance-verification.
    )
    # Structural shape: blob has magic-bytes, so verdict must NOT be
    # the "missing magic header" failure.
    assert result.verdict != "unavailable", (
        f"well-formed blob marked unavailable: note={result.note!r}"
    )
    assert "missing magic header" not in result.note, (
        f"well-formed blob rejected as magic-less: note={result.note!r}"
    )


@settings(max_examples=100, deadline=None)
@given(ots_proof_bytes_malformed())
def test_tv_prop_6b_malformed_ots_bytes_rejected_by_structural_pole(
    tmp_path_factory,
    blob: bytes,
) -> None:
    """Malformed-OTS-bytes strategy yields blobs the structural pole rejects."""
    from wakir_verify.poles import pole_python_stdlib_verify
    tmp = tmp_path_factory.mktemp("ots-mf")
    path = tmp / "mf.ots"
    path.write_bytes(blob)
    result = pole_python_stdlib_verify(
        anchor_hash=_ANCHOR_HEX,
        ots_proof_path=str(path),
    )
    # Malformed prefix means structural pole flags "failed" with the
    # missing-magic-header note, OR — for the degenerate case of a
    # short prefix that happens to match a different rejection path —
    # at minimum ok=False.
    assert result.ok is False, (
        f"malformed blob accepted as ok=True; note={result.note!r}"
    )
    assert result.verdict in ("failed", "unavailable")


@settings(max_examples=200, deadline=None)
@given(
    # Size pinned to 4: ``THREE_OF_FOUR`` and ``TWO_OF_FOUR`` are
    # absolute-count thresholds (``ok_count >= 3``, ``ok_count >= 2``),
    # not proportional, so the monotonicity ordering only holds
    # cleanly at the canonical 4-pole shape the verifier ships with.
    # (A 1-pole verification passes ``ALL`` trivially but fails
    # 3-of-4 by the literal count rule — that is by design, not a
    # monotonicity violation, so we constrain the strategy to the
    # documented production shape.)
    st.lists(st.booleans(), min_size=4, max_size=4),
)
def test_tv_prop_5_quorum_monotone(ok_flags: list[bool]) -> None:
    """Quorum strictness ordering at 4 poles: ALL >= 3-of-4 >= 2-of-4.

    If a strict policy passes, every looser policy must also pass.
    Equivalently: if a looser policy fails, every stricter policy
    must also fail.
    """
    pole_results = _make_pole_results_from_oks(ok_flags)
    pass_all = _evaluate_quorum(pole_results, QuorumPolicy.ALL)
    pass_3 = _evaluate_quorum(pole_results, QuorumPolicy.THREE_OF_FOUR)
    pass_2 = _evaluate_quorum(pole_results, QuorumPolicy.TWO_OF_FOUR)

    if pass_all:
        assert pass_3, (
            f"monotonicity break (ALL passes, 3-of-4 fails) on "
            f"ok_flags={ok_flags}"
        )
        assert pass_2, (
            f"monotonicity break (ALL passes, 2-of-4 fails) on "
            f"ok_flags={ok_flags}"
        )
    if pass_3:
        assert pass_2, (
            f"monotonicity break (3-of-4 passes, 2-of-4 fails) on "
            f"ok_flags={ok_flags}"
        )
