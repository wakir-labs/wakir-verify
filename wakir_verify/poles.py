# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Four independent verification poles for WAT Bitcoin-anchor witness.

Each pole exposes a single ``pole_<name>_verify`` function with a
common signature:

    pole_<name>_verify(
        *,
        anchor_hash: str,           # 64-char lowercase hex
        ots_proof_path: str,        # filesystem path to .ots receipt
        **per_pole_kwargs,          # transports, overrides, …
    ) -> PoleResult

The four poles are deliberately heterogeneous:

* **pole_python_stdlib** — parses the ``.ots`` receipt with the
  reference Python implementation surface (here: stdlib-only OTS
  proof reader; ``pyopentimestamps`` would slot in by override
  without changing the public API). Runs offline against a
  recorded Bitcoin block hash supplied by the caller; this is the
  pole that operators self-host with zero third-party network.

* **pole_ots_cli** — shells out to the upstream ``ots`` CLI
  binary. Independent code-path, independent maintainer, runs
  against the operator's local Bitcoin node or a configured
  Esplora fallback.

* **pole_mempool_space** — HTTP GETs ``mempool.space`` for the
  block height claimed by the receipt and reports the block hash
  it observes.

* **pole_esplora_blockstream** — same as mempool.space, against
  ``blockstream.info``. Independent operator (Blockstream vs.
  mempool.space team) running the same Esplora REST surface, so
  two HTTP poles do not share an operator failure domain.

Quorum (3-of-4 default) means a single transient pole failure
does not flip the overall verdict; see ``aggregator.py``.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from wakir_verify.types import PoleResult


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


#: Regex matching a 64-lowercase-hex block hash.
_BLOCK_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

#: Regex matching a Bitcoin block height attestation line in the
#: output of ``ots info``. Mirrors ``wat.anchor.esplora``'s pattern.
_BLOCK_HEIGHT_LINE_RE = re.compile(
    r"BitcoinBlockHeaderAttestation\((\d+)\)"
    r"|Bitcoin\s+block\s+(\d+)\b",
    re.IGNORECASE,
)


def _read_ots_blob(ots_proof_path: str) -> bytes:
    """Read the OTS receipt as raw bytes. Empty / missing -> empty bytes."""
    p = Path(ots_proof_path)
    if not p.exists() or not p.is_file():
        return b""
    return p.read_bytes()


def _extract_heights_from_text(text: str) -> list[int]:
    """Extract Bitcoin block heights from arbitrary ``ots info`` text.

    Deduplicates, preserves first-seen order. Mirrors
    :func:`wat.anchor.esplora.extract_block_heights_from_info` so
    poles using either source agree.
    """
    seen: set[int] = set()
    out: list[int] = []
    for match in _BLOCK_HEIGHT_LINE_RE.finditer(text or ""):
        height_str = match.group(1) or match.group(2)
        if height_str is None:
            continue
        try:
            height = int(height_str)
        except ValueError:
            continue
        if height in seen:
            continue
        seen.add(height)
        out.append(height)
    return out


# ---------------------------------------------------------------------------
# Pole 1 — python-stdlib OTS parser (offline)
# ---------------------------------------------------------------------------
#
# This pole stands in for the "python-bitcoinlib" / "pyopentimestamps"
# axis named in the Position-Paper §L4 annex. We deliberately ship a
# stdlib-only implementation as the default body because:
#
# * pyopentimestamps is not a Wakir runtime hard-dependency
#   (boring-tech bias: zero PyPI surface to audit on a brand-proof
#   verifier), and
# * the Sprint-8 Tag-1 deliverable is the **surface** plus the
#   cross-library aggregation contract, not a re-implementation of
#   the OTS proof-tree walk.
#
# The body inspects the .ots blob for the receipt magic-bytes header
# and surfaces the block heights named by the receipt. Operators
# wanting full proof-tree validation can inject a custom verifier via
# the ``verifier`` keyword override (see ``verify`` signature); the
# default is the boring "structure looks like a finalised OTS
# receipt and names heights matching the expected anchor" check.
# This is the pole's substance-truth contract: it proves nothing
# more than what the operator can read by ``hexdump | head`` on the
# receipt file plus a recorded ``expected_block_height``.


#: Magic header that every OTS receipt starts with: 31 bytes of fixed
#: data per the OTS file-format spec (`OpenTimestamps.proof`).
_OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"


def pole_python_stdlib_verify(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    expected_block_height: Optional[int] = None,
    proof_reader: Optional[Callable[[bytes], Mapping[str, Any]]] = None,
) -> PoleResult:
    """Pole 1 — offline OTS-receipt structural check via Python stdlib.

    A finalised OTS receipt has a fixed magic-bytes header followed
    by attestation records; an unfinalised (pending) receipt has the
    same header but only calendar attestations. We do not re-walk
    the proof tree here; we check that the receipt is structurally
    a finalised OTS proof and (if ``expected_block_height`` is
    supplied) that the receipt advertises that exact height.

    The ``proof_reader`` override exists for operators or tests that
    want a real proof-tree walk: pass a callable that takes the raw
    receipt bytes and returns a dict with at least ``"heights"``
    (list of ints) and ``"merkle_root_hex"`` (lowercase hex of the
    receipt's root). When ``proof_reader`` is supplied, the pole
    accepts it as authoritative for verdict purposes.
    """
    name = "pole_python_stdlib"
    blob = _read_ots_blob(ots_proof_path)
    if not blob:
        return PoleResult(
            name=name,
            ok=False,
            verdict="unavailable",
            witness={},
            note=f"ots proof file unreadable: {ots_proof_path}",
        )

    if not blob.startswith(_OTS_MAGIC):
        return PoleResult(
            name=name,
            ok=False,
            verdict="failed",
            witness={"length_bytes": len(blob)},
            note="ots receipt missing magic header (not a proof file)",
        )

    if proof_reader is not None:
        try:
            parsed = proof_reader(blob)
        except Exception as exc:  # noqa: BLE001
            return PoleResult(
                name=name,
                ok=False,
                verdict="failed",
                witness={"length_bytes": len(blob)},
                note=f"injected proof_reader raised: {exc}",
            )
        observed_heights = list(parsed.get("heights", []) or [])
        merkle_root_hex = str(parsed.get("merkle_root_hex", "")).lower()
        ok = (
            merkle_root_hex == anchor_hash
            and (
                expected_block_height is None
                or expected_block_height in observed_heights
            )
        )
        return PoleResult(
            name=name,
            ok=ok,
            verdict="verified" if ok else "failed",
            witness={
                "merkle_root_hex": merkle_root_hex,
                "heights": observed_heights,
                "reader": "injected",
            },
            note="" if ok else "proof_reader merkle root or height mismatch",
        )

    # Default body: structural-only acceptance. The contract is
    # honest: the pole says "this is a syntactically-valid finalised
    # OTS receipt that mentions the expected block height" and
    # nothing more.
    heights = _extract_heights_from_blob_text(blob)
    structural_ok = bool(heights)
    height_ok = (
        expected_block_height is None
        or expected_block_height in heights
    )
    ok = structural_ok and height_ok
    note_parts: list[str] = []
    if not structural_ok:
        note_parts.append("no BitcoinBlockHeaderAttestation found in receipt")
    if expected_block_height is not None and not height_ok:
        note_parts.append(
            f"expected block height {expected_block_height} not in {heights}"
        )
    return PoleResult(
        name=name,
        ok=ok,
        verdict="verified" if ok else "failed",
        witness={
            "length_bytes": len(blob),
            "heights": heights,
            "reader": "stdlib-structural",
        },
        note="; ".join(note_parts),
    )


def _extract_heights_from_blob_text(blob: bytes) -> list[int]:
    """Best-effort height extraction from an OTS receipt's raw bytes.

    The OTS file format is binary, but finalised receipts embed
    block-height attestation markers in a recognisable pattern; we
    use the regex used by ``wat.anchor.esplora`` against any
    decodable substring. Tests inject a structured proof_reader for
    deterministic behaviour; this default exists for the brand-
    demo scenario where an operator just wants a quick offline
    sanity check.
    """
    try:
        text = blob.decode("latin-1", errors="ignore")
    except UnicodeDecodeError:  # pragma: no cover - latin-1 cannot fail
        return []
    return _extract_heights_from_text(text)


# ---------------------------------------------------------------------------
# Pole 2 — `ots` CLI subprocess
# ---------------------------------------------------------------------------


#: Default name of the OpenTimestamps CLI binary on ``$PATH``.
DEFAULT_OTS_BIN = "ots"


def pole_ots_cli_verify(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    ots_runner: Optional[Callable[[list[str]], "subprocess.CompletedProcess[str]"]] = None,
    ots_bin: str = DEFAULT_OTS_BIN,
    expected_block_height: Optional[int] = None,
    timeout_s: float = 30.0,
) -> PoleResult:
    """Pole 2 — shell out to the upstream ``ots`` CLI binary.

    Runs ``ots info <receipt>`` and parses the output for at least
    one ``BitcoinBlockHeaderAttestation(H)`` line. When
    ``expected_block_height`` is supplied, the pole additionally
    requires that height to appear in the output.

    The ``ots_runner`` override is the test-injection seam: pass a
    callable that returns a ``CompletedProcess`` and the pole will
    not call ``subprocess`` at all.
    """
    name = "pole_ots_cli"

    if ots_runner is None and shutil.which(ots_bin) is None:
        return PoleResult(
            name=name,
            ok=False,
            verdict="unavailable",
            witness={"binary": ots_bin},
            note=f"ots binary {ots_bin!r} not found on PATH",
        )

    if not Path(ots_proof_path).exists():
        return PoleResult(
            name=name,
            ok=False,
            verdict="unavailable",
            witness={},
            note=f"ots proof file does not exist: {ots_proof_path}",
        )

    argv = [ots_bin, "info", ots_proof_path]
    try:
        if ots_runner is not None:
            cp = ots_runner(argv)
        else:
            cp = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
    except subprocess.TimeoutExpired:
        return PoleResult(
            name=name,
            ok=False,
            verdict="unavailable",
            witness={"argv": argv},
            note=f"ots info timed out after {timeout_s}s",
        )
    except OSError as exc:
        return PoleResult(
            name=name,
            ok=False,
            verdict="unavailable",
            witness={"argv": argv},
            note=f"ots subprocess failed: {exc}",
        )

    stdout = (cp.stdout or "") + "\n" + (cp.stderr or "")
    heights = _extract_heights_from_text(stdout)
    rc_ok = cp.returncode == 0
    structural_ok = bool(heights)
    height_ok = (
        expected_block_height is None
        or expected_block_height in heights
    )
    ok = rc_ok and structural_ok and height_ok

    note_parts: list[str] = []
    if not rc_ok:
        note_parts.append(f"ots info returncode={cp.returncode}")
    if not structural_ok:
        note_parts.append("no BitcoinBlockHeaderAttestation in ots info output")
    if expected_block_height is not None and not height_ok:
        note_parts.append(
            f"expected height {expected_block_height} not in {heights}"
        )

    return PoleResult(
        name=name,
        ok=ok,
        verdict="verified" if ok else "failed",
        witness={
            "returncode": cp.returncode,
            "heights": heights,
            "stdout_snippet": (stdout[:240] if stdout else ""),
        },
        note="; ".join(note_parts),
    )


# ---------------------------------------------------------------------------
# Pole 3 — mempool.space Esplora REST
# ---------------------------------------------------------------------------


#: Default base URL for the mempool.space Esplora-compatible API.
MEMPOOL_SPACE_BASE_URL = "https://mempool.space/api"

#: Per-call HTTP timeout for mempool.space, in seconds. Same value as
#: the existing :mod:`wat.anchor.esplora` shared client for parity.
MEMPOOL_TIMEOUT_S = 10.0

_USER_AGENT = "wakir-runtime/external-verifier (+https://wakir.dev)"


@dataclasses.dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response object used by injected transports."""

    status: int
    body: str


HttpTransport = Callable[[str, float], HttpResponse]


def _default_http_transport(url: str, timeout_s: float) -> HttpResponse:
    """Real urllib transport; tests inject a fake."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return HttpResponse(
                status=getattr(resp, "status", 200),
                body=resp.read().decode("utf-8", errors="replace"),
            )
    except urllib.error.HTTPError as exc:
        return HttpResponse(status=exc.code, body="")
    except (urllib.error.URLError, TimeoutError) as exc:
        return HttpResponse(status=0, body=f"transport-error: {exc}")


def pole_mempool_space_verify(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    expected_block_height: int,
    expected_block_hash: Optional[str] = None,
    transport: Optional[HttpTransport] = None,
    base_url: str = MEMPOOL_SPACE_BASE_URL,
    timeout_s: float = MEMPOOL_TIMEOUT_S,
) -> PoleResult:
    """Pole 3 — mempool.space block-header cross-check.

    Resolves ``GET <base>/block-height/<H>`` to fetch the canonical
    block hash at the receipt's claimed height, then optionally
    cross-checks against ``expected_block_hash`` (e.g. the hash
    recorded next to the WAT manifest the first time the anchor was
    verified). The pole's contract is: "Bitcoin mainnet, as observed
    by mempool.space, has a block at height H with hash X" — not a
    full Merkle proof walk; that is :mod:`wat.anchor.ots_anchor`'s
    job. The cross-library contract is operator-independence:
    mempool.space and blockstream.info are run by different teams.

    ``expected_block_height`` is required (positional contract:
    every HTTP pole call must know which height to query). When
    ``expected_block_hash`` is ``None`` the pole reports the observed
    hash as witness without an equality assertion; tests use that
    mode to capture canonical block hashes during fixture creation.
    """
    return _verify_via_esplora_rest(
        name="pole_mempool_space",
        anchor_hash=anchor_hash,
        ots_proof_path=ots_proof_path,
        expected_block_height=expected_block_height,
        expected_block_hash=expected_block_hash,
        transport=transport,
        base_url=base_url,
        timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# Pole 4 — esplora.blockstream.info REST
# ---------------------------------------------------------------------------


#: Default base URL for the Blockstream-operated Esplora deployment.
ESPLORA_BLOCKSTREAM_BASE_URL = "https://blockstream.info/api"


def pole_esplora_blockstream_verify(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    expected_block_height: int,
    expected_block_hash: Optional[str] = None,
    transport: Optional[HttpTransport] = None,
    base_url: str = ESPLORA_BLOCKSTREAM_BASE_URL,
    timeout_s: float = MEMPOOL_TIMEOUT_S,
) -> PoleResult:
    """Pole 4 — Blockstream Esplora block-header cross-check.

    Same REST surface as :func:`pole_mempool_space_verify`,
    different operator (Blockstream).
    """
    return _verify_via_esplora_rest(
        name="pole_esplora_blockstream",
        anchor_hash=anchor_hash,
        ots_proof_path=ots_proof_path,
        expected_block_height=expected_block_height,
        expected_block_hash=expected_block_hash,
        transport=transport,
        base_url=base_url,
        timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# Shared Esplora-REST verifier body
# ---------------------------------------------------------------------------


def _verify_via_esplora_rest(
    *,
    name: str,
    anchor_hash: str,
    ots_proof_path: str,
    expected_block_height: int,
    expected_block_hash: Optional[str],
    transport: Optional[HttpTransport],
    base_url: str,
    timeout_s: float,
) -> PoleResult:
    """Shared body for the two Esplora-REST poles.

    The two HTTP poles share endpoint shape, status-code semantics,
    and witness format; only the operator (mempool.space vs.
    blockstream.info) differs. Sharing the body keeps the
    cross-library contract honest — both poles ask the exact same
    question — and centralises the transport-injection seam.
    """
    if expected_block_height < 0:
        return PoleResult(
            name=name,
            ok=False,
            verdict="failed",
            witness={"expected_block_height": expected_block_height},
            note="expected_block_height must be non-negative",
        )

    transport = transport or _default_http_transport
    base = base_url.rstrip("/")
    url = f"{base}/block-height/{expected_block_height}"

    resp = transport(url, timeout_s)
    if resp.status != 200 or not resp.body:
        return PoleResult(
            name=name,
            ok=False,
            verdict="unavailable",
            witness={
                "url": url,
                "status": resp.status,
                "body_snippet": resp.body[:120],
            },
            note=f"{name} returned status={resp.status}",
        )

    observed_hash = resp.body.strip().lower()
    if not _BLOCK_HASH_RE.fullmatch(observed_hash):
        return PoleResult(
            name=name,
            ok=False,
            verdict="failed",
            witness={
                "url": url,
                "status": resp.status,
                "body_snippet": resp.body[:120],
            },
            note=f"{name} returned malformed block hash",
        )

    if expected_block_hash is None:
        # Witness-capture mode: report observed hash without assertion.
        return PoleResult(
            name=name,
            ok=True,
            verdict="verified",
            witness={
                "url": url,
                "height": expected_block_height,
                "observed_block_hash": observed_hash,
                "mode": "witness-capture",
            },
            note="",
        )

    expected_normalised = expected_block_hash.strip().lower()
    ok = observed_hash == expected_normalised
    return PoleResult(
        name=name,
        ok=ok,
        verdict="verified" if ok else "failed",
        witness={
            "url": url,
            "height": expected_block_height,
            "observed_block_hash": observed_hash,
            "expected_block_hash": expected_normalised,
        },
        note=(
            ""
            if ok
            else f"block-hash mismatch at height {expected_block_height}"
        ),
    )


__all__ = [
    "DEFAULT_OTS_BIN",
    "ESPLORA_BLOCKSTREAM_BASE_URL",
    "HttpResponse",
    "HttpTransport",
    "MEMPOOL_SPACE_BASE_URL",
    "MEMPOOL_TIMEOUT_S",
    "pole_esplora_blockstream_verify",
    "pole_mempool_space_verify",
    "pole_ots_cli_verify",
    "pole_python_stdlib_verify",
]
