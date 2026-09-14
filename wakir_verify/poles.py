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

The four poles are deliberately heterogeneous, and — since the
2026-09-14 external re-review — they are no longer interchangeable
votes. Two of them can bind the anchor to a Bitcoin attestation; two
of them cannot, and must not be able to outvote the ones that can:

* **pole_python_stdlib** (*mandatory*) — walks the ``.ots`` receipt
  offline with :mod:`wakir_verify.ots_proof`, checks the receipt was
  made for *this* root, and checks the receipt's Bitcoin attestation
  against a block header the caller supplies. No network, no
  third-party dependency; the pole operators self-host.

* **pole_ots_cli** (*mandatory*) — shells out to ``ots verify -d``,
  the upstream subcommand that actually verifies. Independent code
  path, independent maintainer, runs against the operator's Bitcoin
  node.

* **pole_mempool_space** (*supporting*) — HTTP GETs ``mempool.space``
  for a block height and reports the block hash it observes. It
  answers a question about Bitcoin, not about the anchor.

* **pole_esplora_blockstream** (*supporting*) — same question,
  different operator (Blockstream vs. the mempool.space team), so the
  two observations do not share a failure domain.

Why the split exists
--------------------

With four equal votes and a 3-of-4 threshold, a file that was not a
timestamp proof at all — magic header plus the literal text
``BitcoinBlockHeaderAttestation(800000)`` — reached quorum against an
arbitrary root while the ``ots`` pole reported failure. Three poles
that never looked at the root outvoted the one that could have. The
threshold still applies to the supporting evidence, but a positive
verdict now requires a mandatory pole to say so; see
``aggregator.py``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from wakir_verify.ots_proof import (
    BINDING_ROOT_DIRECT,
    BINDING_ROOT_FILE,
    OtsParseError,
    match_anchor_binding,
    parse_ots_receipt,
)
from wakir_verify.types import (
    ROLE_MANDATORY,
    ROLE_SUPPORTING,
    PoleResult,
    VERDICT_BLOCK_OBSERVED,
    VERDICT_FAILED,
    VERDICT_NOT_CHECKED,
    VERDICT_STRUCTURAL_OK,
    VERDICT_UNAVAILABLE,
    VERDICT_VERIFIED,
)


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
# Pole 1 — offline OTS proof walk (mandatory)
# ---------------------------------------------------------------------------
#
# This pole stands in for the "python-bitcoinlib" / "pyopentimestamps"
# axis named in the Position-Paper §L4 annex. It stays stdlib-only
# (boring-tech bias: zero PyPI surface to audit on a brand-proof
# verifier), but "stdlib-only" is no longer an excuse for "structural
# guess": the proof-tree walk lives in ``wakir_verify.ots_proof`` and
# the pole binds the caller's root to the receipt before it says
# anything positive.
#
# What the pole cannot do alone is confirm the Bitcoin side: a block
# header is not in the receipt. That input is a parameter, and its
# absence is reported as ``not_checked`` rather than papered over.


def pole_python_stdlib_verify(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    expected_block_height: Optional[int] = None,
    proof_reader: Optional[Callable[[bytes], Mapping[str, Any]]] = None,
    block_merkle_roots: Optional[Mapping[int, str]] = None,
) -> PoleResult:
    """Pole 1 — offline, root-bound OTS-receipt verification (mandatory).

    Walks the receipt with :mod:`wakir_verify.ots_proof` and answers
    three questions in order, stopping at the first negative:

    1. Does this parse as an OpenTimestamps receipt?
    2. Was it made for *this* ``anchor_hash``? (``file_digest``
       compared against both accepted bindings — see
       :func:`~wakir_verify.ots_proof.match_anchor_binding`.)
    3. Does a Bitcoin attestation in it check out against a real block?

    Question 3 needs a block header, which is not in the receipt. Pass
    ``block_merkle_roots`` as ``{height: merkle_root_hex}`` in
    block-explorer display order — from a Bitcoin node, from a pinned
    fixture, or from an operator's own records. Without it the pole
    reports ``not_checked`` and puts the receipt's *claims* in the
    witness so the operator can check them by hand, the same courtesy
    upstream ``ots verify`` extends when Bitcoin is disabled.

    What this pole will never do again is answer "verified" to a
    question about a root it never looked at. The previous default
    body regex-scanned the receipt bytes for the text
    ``BitcoinBlockHeaderAttestation(H)`` and ignored ``anchor_hash``
    entirely; a file containing the magic header and that string
    passed for any anchor, while every real receipt — whose
    attestations are binary — failed.

    The ``proof_reader`` override is unchanged: pass a callable taking
    the raw bytes and returning ``{"heights": [...],
    "merkle_root_hex": "..."}``, and the pole treats it as
    authoritative.
    """
    name = "pole_python_stdlib"
    blob = _read_ots_blob(ots_proof_path)
    if not blob:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_UNAVAILABLE,
            witness={},
            note=f"ots proof file unreadable: {ots_proof_path}",
            role=ROLE_MANDATORY,
        )

    if proof_reader is not None:
        return _pole_1_via_proof_reader(
            name=name,
            blob=blob,
            anchor_hash=anchor_hash,
            expected_block_height=expected_block_height,
            proof_reader=proof_reader,
        )

    try:
        receipt = parse_ots_receipt(blob)
    except OtsParseError as exc:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness={"length_bytes": len(blob)},
            note=f"not a readable OpenTimestamps receipt: {exc}",
            role=ROLE_MANDATORY,
        )

    binding = match_anchor_binding(anchor_hash, receipt)
    witness: dict[str, Any] = {
        "length_bytes": len(blob),
        "reader": "stdlib-ots-walk",
        "binding": binding.to_dict(),
        "heights": receipt.heights,
        "attestations": [a.to_dict() for a in receipt.attestations],
    }

    if not binding.bound:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness=witness,
            note=(
                "receipt does not attest this root: its file digest is "
                f"{receipt.file_digest_hex}, which matches neither "
                f"{anchor_hash} nor SHA-256 of that root's bytes"
            ),
            role=ROLE_MANDATORY,
        )

    bitcoin = list(receipt.bitcoin_attestations)
    if not bitcoin:
        pending = len(receipt.pending_attestations)
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_STRUCTURAL_OK,
            witness=witness,
            note=(
                "receipt is bound to this root but carries no Bitcoin "
                f"attestation ({pending} pending calendar attestation(s)); "
                "the timestamp has not been upgraded, so there is no "
                "Bitcoin claim to verify"
            ),
            role=ROLE_MANDATORY,
        )

    if expected_block_height is not None:
        bitcoin = [a for a in bitcoin if a.height == expected_block_height]
        if not bitcoin:
            return PoleResult(
                name=name,
                ok=False,
                verdict=VERDICT_FAILED,
                witness=witness,
                note=(
                    f"expected block height {expected_block_height} not "
                    f"attested; receipt names {receipt.heights}"
                ),
                role=ROLE_MANDATORY,
            )

    claims = [
        {
            "height": a.height,
            "claimed_block_merkle_root": a.block_merkle_root_display,
        }
        for a in bitcoin
    ]
    witness["bitcoin_claims"] = claims

    known = {
        int(h): str(v).strip().lower()
        for h, v in (block_merkle_roots or {}).items()
    }
    confirmed: list[dict[str, Any]] = []
    contradicted: list[dict[str, Any]] = []
    for att in bitcoin:
        expected_root = known.get(int(att.height or -1))
        if expected_root is None:
            continue
        observed = att.block_merkle_root_display
        record = {
            "height": att.height,
            "claimed_block_merkle_root": observed,
            "block_header_merkle_root": expected_root,
        }
        (confirmed if observed == expected_root else contradicted).append(record)

    witness["confirmed"] = confirmed
    witness["contradicted"] = contradicted

    if contradicted:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness=witness,
            note=(
                "the receipt's Bitcoin attestation does not match the block "
                f"header supplied for height {contradicted[0]['height']}"
            ),
            role=ROLE_MANDATORY,
        )

    if confirmed:
        return PoleResult(
            name=name,
            ok=True,
            verdict=VERDICT_VERIFIED,
            witness=witness,
            note=(
                f"root bound via {binding.mode}; Bitcoin block "
                f"{confirmed[0]['height']} carries the attested merkle root"
            ),
            role=ROLE_MANDATORY,
        )

    manual = "; ".join(
        f"block {c['height']} should have merkleroot "
        f"{c['claimed_block_merkle_root']}"
        for c in claims
    )
    return PoleResult(
        name=name,
        ok=False,
        verdict=VERDICT_NOT_CHECKED,
        witness=witness,
        note=(
            f"root bound to this receipt via {binding.mode}, but no block "
            "header was supplied to confirm the Bitcoin side. To verify "
            f"manually: {manual}"
        ),
        role=ROLE_MANDATORY,
    )


def _pole_1_via_proof_reader(
    *,
    name: str,
    blob: bytes,
    anchor_hash: str,
    expected_block_height: Optional[int],
    proof_reader: Callable[[bytes], Mapping[str, Any]],
) -> PoleResult:
    """Pole 1 under an injected proof reader, which is authoritative."""
    try:
        parsed = proof_reader(blob)
    except Exception as exc:  # noqa: BLE001 - reader is caller-supplied
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness={"length_bytes": len(blob)},
            note=f"injected proof_reader raised: {exc}",
            role=ROLE_MANDATORY,
        )
    observed_heights = list(parsed.get("heights", []) or [])
    merkle_root_hex = str(parsed.get("merkle_root_hex", "")).lower()
    root_ok = merkle_root_hex == anchor_hash
    height_ok = (
        expected_block_height is None
        or expected_block_height in observed_heights
    )
    ok = root_ok and height_ok
    return PoleResult(
        name=name,
        ok=ok,
        verdict=VERDICT_VERIFIED if ok else VERDICT_FAILED,
        witness={
            "merkle_root_hex": merkle_root_hex,
            "heights": observed_heights,
            "reader": "injected",
        },
        note="" if ok else "proof_reader merkle root or height mismatch",
        role=ROLE_MANDATORY,
    )


# ---------------------------------------------------------------------------
# Pole 2 — `ots` CLI subprocess
# ---------------------------------------------------------------------------


#: Default name of the OpenTimestamps CLI binary on ``$PATH``.
DEFAULT_OTS_BIN = "ots"

#: ``ots verify`` — the upstream subcommand that actually checks a
#: timestamp. Exits non-zero unless a Bitcoin attestation verified
#: against a block header.
OTS_MODE_VERIFY = "verify"
#: ``ots info`` — the upstream subcommand that *prints* a timestamp.
#: Kept for evidence capture; it can never produce a positive verdict.
OTS_MODE_INFO = "info"

#: stderr fragments that mean "I could not perform the check", as
#: opposed to "the check failed". Sourced from otsclient/cmds.py
#: (fetched 2026-09-14, HTTP 200).
_OTS_UNAVAILABLE_MARKERS = (
    "could not connect to local bitcoin node",
    "not checking bitcoin attestation",
    "bitcoin disabled",
    "is highest known block",
    "could not connect",
    "failed to upgrade",
    "could not be upgraded",
)


def pole_ots_cli_verify(
    *,
    anchor_hash: str,
    ots_proof_path: str,
    ots_runner: Optional[Callable[[list[str]], "subprocess.CompletedProcess[str]"]] = None,
    ots_bin: str = DEFAULT_OTS_BIN,
    expected_block_height: Optional[int] = None,
    timeout_s: float = 30.0,
    mode: str = OTS_MODE_VERIFY,
) -> PoleResult:
    """Pole 2 — upstream ``ots`` CLI (mandatory in ``verify`` mode).

    Runs ``ots verify -d <digest> <receipt>``. Upstream separates the
    two subcommands deliberately: ``ots info`` deserialises and prints,
    ``ots verify`` compares the digest, upgrades pending attestations
    and checks a Bitcoin attestation against a block header, exiting
    non-zero if any of that fails (``otsclient/cmds.py::verify_command``
    and ``::verify_timestamp``, fetched 2026-09-14, HTTP 200 from
    https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/otsclient/cmds.py).
    This pole used to run ``info`` and grep its output for a height —
    a display command standing in for a check.

    Because a WAT anchor can reach a receipt either as a stamped file
    or as a stamped digest, the pole offers ``sha256(root-bytes)``
    first and retries with the bare root only if upstream reports a
    digest mismatch. Both being rejected is a genuine root-binding
    failure, not an inconclusive run.

    ``mode=OTS_MODE_INFO`` keeps the old ``ots info`` call available
    for evidence capture. In that mode the pole is *supporting* and
    its best verdict is ``structural_ok``: ``info`` does not verify.

    ``ots_runner`` is the injection seam; when supplied, no
    subprocess is started.
    """
    name = "pole_ots_cli"
    role = ROLE_MANDATORY if mode == OTS_MODE_VERIFY else ROLE_SUPPORTING

    if mode not in (OTS_MODE_VERIFY, OTS_MODE_INFO):
        raise ValueError(f"unknown ots mode: {mode!r}")

    if ots_runner is None and shutil.which(ots_bin) is None:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_UNAVAILABLE,
            witness={"binary": ots_bin, "mode": mode},
            note=f"ots binary {ots_bin!r} not found on PATH",
            role=role,
        )

    if not Path(ots_proof_path).exists():
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_UNAVAILABLE,
            witness={"mode": mode},
            note=f"ots proof file does not exist: {ots_proof_path}",
            role=role,
        )

    if mode == OTS_MODE_INFO:
        return _pole_2_info(
            name=name,
            ots_bin=ots_bin,
            ots_proof_path=ots_proof_path,
            ots_runner=ots_runner,
            expected_block_height=expected_block_height,
            timeout_s=timeout_s,
        )

    attempts: list[dict[str, Any]] = []
    last: Optional[dict[str, Any]] = None
    for binding_mode, digest in _anchor_digest_candidates(anchor_hash):
        argv = [ots_bin, "verify", "-d", digest, ots_proof_path]
        run = _run_ots(
            argv=argv,
            ots_runner=ots_runner,
            timeout_s=timeout_s,
        )
        if run.get("error"):
            return PoleResult(
                name=name,
                ok=False,
                verdict=VERDICT_UNAVAILABLE,
                witness={"argv": argv, "mode": mode},
                note=str(run["error"]),
                role=role,
            )
        run["binding_mode"] = binding_mode
        run["digest"] = digest
        attempts.append(
            {
                "binding_mode": binding_mode,
                "digest": digest,
                "returncode": run["returncode"],
                "output_snippet": run["output"][:240],
            }
        )
        last = run
        if run["returncode"] == 0:
            break
        if "digest provided does not match" not in run["output"].lower():
            break

    assert last is not None  # the candidate list is never empty
    output = last["output"]
    lower = output.lower()
    witness = {
        "mode": mode,
        "attempts": attempts,
        "returncode": last["returncode"],
        "binding_mode": last["binding_mode"],
        "heights": _extract_heights_from_text(output),
        "stdout_snippet": output[:240],
    }

    if last["returncode"] == 0:
        height_ok = (
            expected_block_height is None
            or expected_block_height in witness["heights"]
            or not witness["heights"]
        )
        if not height_ok:
            return PoleResult(
                name=name,
                ok=False,
                verdict=VERDICT_FAILED,
                witness=witness,
                note=(
                    f"ots verify succeeded but named heights "
                    f"{witness['heights']}, not {expected_block_height}"
                ),
                role=role,
            )
        return PoleResult(
            name=name,
            ok=True,
            verdict=VERDICT_VERIFIED,
            witness=witness,
            note=f"ots verify -d ({last['binding_mode']}) confirmed the anchor",
            role=role,
        )

    if any(marker in lower for marker in _OTS_UNAVAILABLE_MARKERS):
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_UNAVAILABLE,
            witness=witness,
            note=(
                "ots verify could not complete the Bitcoin check "
                f"(returncode {last['returncode']}): {output.strip()[:160]}"
            ),
            role=role,
        )

    return PoleResult(
        name=name,
        ok=False,
        verdict=VERDICT_FAILED,
        witness=witness,
        note=(
            f"ots verify rejected the timestamp (returncode "
            f"{last['returncode']}): {output.strip()[:160]}"
        ),
        role=role,
    )


def _anchor_digest_candidates(anchor_hash: str) -> list[tuple[str, str]]:
    """Digests to offer ``ots verify -d``, most likely binding first."""
    anchor = (anchor_hash or "").strip().lower()
    candidates: list[tuple[str, str]] = []
    try:
        raw = bytes.fromhex(anchor)
    except ValueError:
        raw = b""
    if len(raw) == 32:
        candidates.append(
            (BINDING_ROOT_FILE, hashlib.sha256(raw).hexdigest())
        )
    if anchor:
        candidates.append((BINDING_ROOT_DIRECT, anchor))
    return candidates or [(BINDING_ROOT_DIRECT, anchor)]


def _run_ots(
    *,
    argv: list[str],
    ots_runner: Optional[Callable[[list[str]], "subprocess.CompletedProcess[str]"]],
    timeout_s: float,
) -> dict[str, Any]:
    """Run the ``ots`` CLI (or the injected runner) and flatten output."""
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
        return {"error": f"ots timed out after {timeout_s}s"}
    except OSError as exc:
        return {"error": f"ots subprocess failed: {exc}"}
    output = (cp.stdout or "") + "\n" + (cp.stderr or "")
    return {"returncode": cp.returncode, "output": output, "error": None}


def _pole_2_info(
    *,
    name: str,
    ots_bin: str,
    ots_proof_path: str,
    ots_runner: Optional[Callable[[list[str]], "subprocess.CompletedProcess[str]"]],
    expected_block_height: Optional[int],
    timeout_s: float,
) -> PoleResult:
    """``ots info`` evidence capture. Cannot produce a positive verdict."""
    argv = [ots_bin, "info", ots_proof_path]
    run = _run_ots(argv=argv, ots_runner=ots_runner, timeout_s=timeout_s)
    if run.get("error"):
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_UNAVAILABLE,
            witness={"argv": argv, "mode": OTS_MODE_INFO},
            note=str(run["error"]),
            role=ROLE_SUPPORTING,
        )

    output = run["output"]
    heights = _extract_heights_from_text(output)
    rc_ok = run["returncode"] == 0
    height_ok = (
        expected_block_height is None or expected_block_height in heights
    )
    witness = {
        "mode": OTS_MODE_INFO,
        "returncode": run["returncode"],
        "heights": heights,
        "stdout_snippet": output[:240],
    }

    if not rc_ok:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness=witness,
            note=f"ots info returncode={run['returncode']}",
            role=ROLE_SUPPORTING,
        )
    if not heights:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_STRUCTURAL_OK,
            witness=witness,
            note="ots info printed no BitcoinBlockHeaderAttestation line",
            role=ROLE_SUPPORTING,
        )
    if not height_ok:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness=witness,
            note=f"expected height {expected_block_height} not in {heights}",
            role=ROLE_SUPPORTING,
        )
    return PoleResult(
        name=name,
        ok=True,
        verdict=VERDICT_STRUCTURAL_OK,
        witness=witness,
        note=(
            "ots info reported block height(s) "
            f"{heights}; `info` displays a timestamp, it does not verify one"
        ),
        role=ROLE_SUPPORTING,
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
    full Merkle proof walk, and not a statement about the anchor.
    That is why its best verdict is ``block_observed`` and why it is
    a *supporting* pole: the docstring always said this honestly, but
    the result field used to say ``verified`` anyway. The cross-library contract is operator-independence:
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
            verdict=VERDICT_FAILED,
            witness={"expected_block_height": expected_block_height},
            note="expected_block_height must be non-negative",
            role=ROLE_SUPPORTING,
        )

    transport = transport or _default_http_transport
    base = base_url.rstrip("/")
    url = f"{base}/block-height/{expected_block_height}"

    resp = transport(url, timeout_s)
    if resp.status != 200 or not resp.body:
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_UNAVAILABLE,
            witness={
                "url": url,
                "status": resp.status,
                "body_snippet": resp.body[:120],
            },
            note=f"{name} returned status={resp.status}",
            role=ROLE_SUPPORTING,
        )

    observed_hash = resp.body.strip().lower()
    if not _BLOCK_HASH_RE.fullmatch(observed_hash):
        return PoleResult(
            name=name,
            ok=False,
            verdict=VERDICT_FAILED,
            witness={
                "url": url,
                "status": resp.status,
                "body_snippet": resp.body[:120],
            },
            note=f"{name} returned malformed block hash",
            role=ROLE_SUPPORTING,
        )

    if expected_block_hash is None:
        # Witness-capture mode: report observed hash without assertion.
        # ``block_observed``, never ``verified`` — the pole asserted
        # nothing, it wrote down what an endpoint said.
        return PoleResult(
            name=name,
            ok=True,
            verdict=VERDICT_BLOCK_OBSERVED,
            witness={
                "url": url,
                "height": expected_block_height,
                "observed_block_hash": observed_hash,
                "mode": "witness-capture",
            },
            note=(
                "observation only: no expected_block_hash was supplied, so "
                "nothing was compared"
            ),
            role=ROLE_SUPPORTING,
        )

    expected_normalised = expected_block_hash.strip().lower()
    ok = observed_hash == expected_normalised
    return PoleResult(
        name=name,
        ok=ok,
        verdict=VERDICT_BLOCK_OBSERVED if ok else VERDICT_FAILED,
        witness={
            "url": url,
            "height": expected_block_height,
            "observed_block_hash": observed_hash,
            "expected_block_hash": expected_normalised,
        },
        note=(
            (
                "the endpoint's block hash at this height matches the "
                "recorded one; this says the chain looks as expected, not "
                "that the anchor is in it"
            )
            if ok
            else f"block-hash mismatch at height {expected_block_height}"
        ),
        role=ROLE_SUPPORTING,
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
