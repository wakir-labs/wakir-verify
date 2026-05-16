# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Multi-version python-bitcoinlib drift probe (Sprint-8 Tag-4 Teil B).

Background
----------

The 4-pole external verifier names ``python-bitcoinlib`` as the
canonical "stdlib OTS parser" axis in the Position-Paper §L4-References
annex. Today the structural pole ships a stdlib-only body (no real
``python-bitcoinlib`` import) because the verifier sub-package keeps a
zero-PyPI-surface posture for brand-proof reasons. But a third party
auditing the trail may well install ``python-bitcoinlib`` and inject
its own ``proof_reader`` callable; if a future ``python-bitcoinlib``
release drifts on the block-hash byte order, hex casing, or magic-
header offset, the auditor's verification would silently disagree
with the verifier.

This module is the canary. It is skipped when ``python-bitcoinlib`` is
not installed (the default in the standard test lane) and runs a
minimal cross-check when the CI matrix installs the library against
one of the pinned versions ("0.11.2" / "0.12.1" / "0.12.2"). The
matrix is wired in ``.github/workflows/external-verifier-drift.yml``.

What we actually probe
----------------------

We exercise three small invariants that the verifier sub-package
depends on (or would depend on the moment an auditor injects a
``python-bitcoinlib``-backed ``proof_reader``):

* **DRIFT-1 — block hash canonicalisation is stable.**
  ``bitcoin.core.b2lx`` / ``b2x`` produce the same 64-hex-char
  lowercase string for the same 32-byte hash across versions. If a
  future release changes endianness or casing, this fails loud.

* **DRIFT-2 — OP_RETURN script parsing accepts the canonical
  attestation marker.**
  The OTS receipt's BitcoinBlockHeaderAttestation lands in an
  OP_RETURN output. We instantiate the script primitive
  (``CScript([OP_RETURN, b"..."])``) and round-trip its hex form.
  Drift here would mean the auditor's hash-of-script changes
  silently.

* **DRIFT-3 — version sanity probe.**
  ``bitcoin.__version__`` exists and parses. This catches a packaging
  regression where ``pip install python-bitcoinlib==X`` resolves but
  the installed module is unexpectedly empty or aliased.
"""

from __future__ import annotations

import pytest

# Skip the whole module when python-bitcoinlib is absent. The standard
# test lane runs without it; the dedicated drift-matrix workflow
# installs it pinned to one version per matrix-job.
bitcoin = pytest.importorskip(
    "bitcoin",
    reason="python-bitcoinlib not installed; drift probe is matrix-only",
)


# ---------------------------------------------------------------------------
# DRIFT-1: block-hash canonicalisation
# ---------------------------------------------------------------------------


def test_drift_1_block_hash_b2lx_byte_order_stable() -> None:
    """``bitcoin.core.b2lx`` reverses byte order to display form.

    A real Bitcoin block hash is stored internally as little-endian
    bytes and rendered to humans as big-endian hex (the historical
    Satoshi-display convention). The verifier's HTTP poles compare
    against the *display* form (what ``mempool.space`` and
    ``blockstream.info`` return). If a future ``python-bitcoinlib``
    swapped ``b2lx`` semantics, an injected ``proof_reader`` would
    quietly emit byte-swapped hashes.
    """
    from bitcoin.core import b2lx, b2x

    # Synthetic 32-byte hash: easy to read both orders.
    raw = bytes(range(32))
    display = b2lx(raw)
    raw_hex = b2x(raw)

    # ``b2lx`` MUST reverse byte order vs. ``b2x``.
    assert display == raw_hex[::-1] or display == "".join(
        raw_hex[i : i + 2] for i in range(62, -2, -2)
    ), (
        f"b2lx byte-order contract drifted: b2lx={display!r} "
        f"b2x={raw_hex!r} (expected b2lx == reversed-byte-pairs of b2x)"
    )
    assert display == display.lower(), (
        f"b2lx casing drifted; expected lowercase, got {display!r}"
    )
    assert len(display) == 64
    assert all(c in "0123456789abcdef" for c in display)


# ---------------------------------------------------------------------------
# DRIFT-2: OP_RETURN script round-trip
# ---------------------------------------------------------------------------


def test_drift_2_op_return_script_round_trips() -> None:
    """``CScript([OP_RETURN, b"..."])`` serialises and re-parses cleanly.

    Drift here would mean that two different python-bitcoinlib
    versions disagree on the canonical byte form of an OP_RETURN
    output, which an auditor would notice the moment they hash the
    script bytes for a cross-check.
    """
    from bitcoin.core.script import CScript, OP_RETURN

    payload = b"BitcoinBlockHeaderAttestation"
    script = CScript([OP_RETURN, payload])
    raw_bytes = bytes(script)

    # The script must begin with the OP_RETURN opcode (0x6a per BIP-11)
    # and contain the payload after a length prefix. The exact prefix
    # encoding depends on payload size; for our 29-byte payload we
    # expect the bare length byte (0x1d).
    assert raw_bytes[0] == OP_RETURN, (
        f"OP_RETURN opcode at offset 0 drifted: got {raw_bytes[0]:#04x}, "
        f"expected {OP_RETURN:#04x}"
    )
    # Round-trip: re-parse the serialised bytes back to a CScript and
    # extract the data-push.
    reparsed = CScript(raw_bytes)
    iter_ops = list(reparsed)
    # First op is OP_RETURN; second is the data-push.
    assert iter_ops[0] == OP_RETURN
    assert iter_ops[1] == payload, (
        f"OP_RETURN payload drifted on round-trip: got {iter_ops[1]!r}, "
        f"expected {payload!r}"
    )


# ---------------------------------------------------------------------------
# DRIFT-3: version sanity probe
# ---------------------------------------------------------------------------


def test_drift_3_version_sanity() -> None:
    """``bitcoin.__version__`` exists and is a non-empty dotted string.

    Catches a packaging-regression where ``pip install
    python-bitcoinlib==X`` resolves but the installed module is
    unexpectedly empty / aliased / unversioned.
    """
    version = getattr(bitcoin, "__version__", None)
    assert version is not None, "bitcoin.__version__ missing"
    assert isinstance(version, str), (
        f"bitcoin.__version__ has wrong type: {type(version).__name__}"
    )
    assert version, "bitcoin.__version__ is empty"
    # Loose shape: at least one dot, version components are digits.
    parts = version.split(".")
    assert len(parts) >= 2, f"version shape unexpected: {version!r}"
    # python-bitcoinlib uses ``X.Y.Z`` or ``X.Y.Z-postN``; the first
    # two components must be all-digit.
    for p in parts[:2]:
        assert p.isdigit() or (p.split("-")[0].isdigit()), (
            f"version component non-digit: {version!r} parts={parts}"
        )
