# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Hermetic fixtures for the 4-pole external-verifier test suite.

Every fixture is a small Python value that the test functions drive
into the pole implementations via the documented injection seams
(``proof_reader``, ``ots_runner``, ``transport``). No fixture
touches the network.

Test-vectors materialise the Position-Paper §L4 claims:

* **TV-EV-1 — known-good-anchor**
  A finalised OTS receipt and a recorded canonical block hash that
  all four poles agree on; default 3-of-4 verdict is ``verified``.

* **TV-EV-2 — tampered-anchor (single-bit flip)**
  Same receipt but the caller asks for the wrong anchor hash; pole 1
  (offline structural) is silent on hash equality but the injected
  ``proof_reader`` notices the mismatch; HTTP poles see a different
  expected block hash than mempool/blockstream report; quorum fails.

* **TV-EV-3 — wrong-height-tamper**
  The caller claims the receipt anchors block 999_999 but the OTS
  CLI output names block 948183; pole 2 (ots-cli) and pole 1
  (structural) both reject; HTTP poles return the canonical hash for
  the wrong height; quorum fails.

* **TV-EV-4 — partial-witness-quorum-pass (3-of-4)**
  One HTTP pole returns 503; the remaining three poles agree.
  Default 3-of-4 quorum passes; ``--pols all`` would fail.

* **TV-EV-5 — partial-witness-fail-strict (2-of-4 unavailable)**
  Both HTTP poles return 503. Two offline poles agree. Under 3-of-4
  the verdict is failed; under 2-of-4 it would pass (debug-only).
"""

from __future__ import annotations

import dataclasses
from typing import Callable

from wakir_verify.poles import HttpResponse


# ---------------------------------------------------------------------------
# OTS receipt blobs
# ---------------------------------------------------------------------------

#: Minimal OTS-magic-bytes header. Sufficient for the structural
#: pole's positive path; the rest of a real receipt is a binary
#: proof tree we do not need to reproduce for unit tests.
_OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"

#: A receipt that names block height 948183 in its info-text form
#: (the structural pole regexes against the decoded bytes).
RECEIPT_948183_BYTES = (
    _OTS_MAGIC
    + b"BitcoinBlockHeaderAttestation(948183)\n"
    + b"\x00" * 32
)

#: A receipt that names *no* block height (pending receipt).
RECEIPT_PENDING_BYTES = _OTS_MAGIC + b"PendingAttestation(alice.calendar)\n"


# ---------------------------------------------------------------------------
# Canonical block hash for height 948183
# ---------------------------------------------------------------------------

#: Fabricated canonical block hash for the test-only height 948183.
#: All HTTP fakes return this when asked for height 948183. No claim
#: of correspondence to a real Bitcoin block.
BLOCK_HASH_948183 = (
    "0000000000000000000a1d2c3b4e5f60718293a4b5c6d7e8f90123456789abcd"
)


# ---------------------------------------------------------------------------
# Injected callables (proof_reader / ots_runner / transport)
# ---------------------------------------------------------------------------


def make_proof_reader(
    *,
    merkle_root_hex: str,
    heights: list[int],
) -> Callable[[bytes], dict]:
    """Returns a deterministic ``proof_reader`` for pole 1."""

    def _read(blob: bytes) -> dict:
        return {"merkle_root_hex": merkle_root_hex, "heights": list(heights)}

    return _read


@dataclasses.dataclass
class _CompletedProcessStub:
    stdout: str
    stderr: str = ""
    returncode: int = 0


def make_ots_runner(
    *,
    stdout: str,
    returncode: int = 0,
) -> Callable[[list[str]], _CompletedProcessStub]:
    """Returns a deterministic ``ots_runner`` for pole 2."""

    def _run(argv: list[str]) -> _CompletedProcessStub:
        return _CompletedProcessStub(stdout=stdout, returncode=returncode)

    return _run


def make_http_transport(
    *,
    block_hash_by_height: dict[int, str],
    failure_status_for_heights: dict[int, int] | None = None,
) -> Callable[[str, float], HttpResponse]:
    """Returns a deterministic ``transport`` for poles 3 and 4.

    The transport answers ``GET <base>/block-height/<H>`` from the
    supplied mapping; any other URL shape returns status 0 (transport
    error). ``failure_status_for_heights`` lets a test simulate a
    pole-specific outage (e.g. mempool.space returning 503 while
    blockstream.info still answers).
    """
    failure_status_for_heights = failure_status_for_heights or {}

    def _transport(url: str, timeout_s: float) -> HttpResponse:
        # Expected URL shape: ".../block-height/<H>".
        marker = "/block-height/"
        if marker not in url:
            return HttpResponse(status=0, body="unsupported url shape")
        height_str = url.rsplit(marker, 1)[1].strip()
        try:
            height = int(height_str)
        except ValueError:
            return HttpResponse(status=400, body=f"bad height {height_str!r}")
        if height in failure_status_for_heights:
            return HttpResponse(
                status=failure_status_for_heights[height],
                body="",
            )
        if height not in block_hash_by_height:
            return HttpResponse(status=404, body="")
        return HttpResponse(
            status=200,
            body=block_hash_by_height[height] + "\n",
        )

    return _transport


__all__ = [
    "BLOCK_HASH_948183",
    "RECEIPT_948183_BYTES",
    "RECEIPT_PENDING_BYTES",
    "make_http_transport",
    "make_ots_runner",
    "make_proof_reader",
]
