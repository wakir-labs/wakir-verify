# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Stdlib OpenTimestamps receipt parser — the root-binding read half.

Why this module exists
----------------------

Before this module, the offline pole in :mod:`wakir_verify.poles`
decided "is this a valid anchor?" by regex-scanning the receipt's raw
bytes for the *text* ``BitcoinBlockHeaderAttestation(H)`` and looking
for the 31-byte magic header. That check never touched
``anchor_hash``: a hand-made file consisting of the magic header plus
that text string passed, and passed for *any* anchor hash handed to
it. A real receipt, whose attestations are binary records that never
contain that text, failed. The check was therefore not merely weak —
it was inverted.

This module replaces the regex with an actual walk of the receipt.

What the format is
------------------

An ``.ots`` detached timestamp file is::

    <31-byte magic> <varuint major version>
    <1-byte file-hash-op tag> <digest bytes>
    <timestamp tree>

The timestamp tree is a sequence of unary operations applied to a
running message, with forks (``0xff``) where one message feeds several
continuations, and attestations (``0x00`` + 8-byte notary tag +
varbytes payload) at the leaves. For a Bitcoin attestation the running
message *at that point in the tree* is the Merkle root of the block at
the attested height — the same value upstream ``ots`` prints as
``To verify manually, check that Bitcoin block %d has merkleroot %s``
(``otsclient/cmds.py::verify_timestamp``, fetched 2026-09-14, HTTP 200
from https://raw.githubusercontent.com/opentimestamps/opentimestamps-client/master/otsclient/cmds.py).

Two facts this buys us that the regex could not
-----------------------------------------------

1. **Root binding.** ``file_digest`` is the digest the receipt was
   made for. Comparing it to the caller's ``anchor_hash`` is the
   check that makes "this receipt attests *this* root" a statement
   with content. Upstream does the same in ``ots verify -d``.

2. **An explicit, checkable Bitcoin claim.** Each Bitcoin attestation
   yields ``(height, claimed_block_merkle_root)``. Confirming that
   claim needs a block header from somewhere outside this file — a
   Bitcoin node or a block explorer. This module does not invent that
   confirmation and does not pretend the claim is the confirmation:
   an unconfirmed claim is reported as a claim.

Scope
-----

Read-only, stdlib-only, no network. Deserialisation limits mirror
python-opentimestamps (``MAX_PAYLOAD_SIZE`` 8192, ``MAX_URI_LENGTH``
1000) plus a total-operation budget so a malformed or hostile receipt
cannot turn the verifier into a decompression bomb.
"""

from __future__ import annotations

import binascii
import dataclasses
import hashlib
from typing import Any, Dict, List, Optional, Tuple


#: Magic header every OTS detached-timestamp file starts with.
OTS_MAGIC = (
    b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
)

#: Major version this reader understands.
SUPPORTED_MAJOR_VERSION = 1

#: Notary tags (python-opentimestamps ``TimeAttestation`` subclasses).
TAG_BITCOIN = b"\x05\x88\x96\x0d\x73\xd7\x19\x01"
TAG_PENDING = b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e"
TAG_LITECOIN = b"\x06\x86\x9a\x0d\x73\xd7\x1b\x45"
TAG_ETHEREUM = b"\x30\xfe\x80\x87\xb5\xc7\xea\xd7"

#: Attestation payloads are bounded upstream; mirror the bound.
MAX_PAYLOAD_SIZE = 8192
#: Pending-attestation URIs are bounded upstream; mirror the bound.
MAX_URI_LENGTH = 1000
#: Total tree operations we are willing to execute for one receipt.
MAX_OPS = 10_000
#: Largest append/prepend operand we accept (upstream bound).
MAX_OPERAND_SIZE = 4096

#: File-hash ops: tag -> (name, digest length in bytes).
_FILE_HASH_OPS: Dict[int, Tuple[str, int]] = {
    0x02: ("sha1", 20),
    0x03: ("ripemd160", 20),
    0x08: ("sha256", 32),
    0x67: ("keccak256", 32),
}


class OtsParseError(ValueError):
    """The byte stream is not a readable OpenTimestamps receipt."""


@dataclasses.dataclass(frozen=True)
class Attestation:
    """One notary attestation found in the receipt's proof tree.

    Attributes
    ----------
    kind:
        ``"bitcoin"``, ``"pending"``, ``"litecoin"``, ``"ethereum"``
        or ``"unknown"``.
    message_hex:
        The running message at this point of the tree, lowercase hex.
        For ``kind == "bitcoin"`` this is the Merkle root the
        attestation claims the block at ``height`` has, in Bitcoin's
        internal byte order.
    height:
        Block height for chain attestations, otherwise ``None``.
    uri:
        Calendar URI for pending attestations, otherwise ``None``.
    """

    kind: str
    message_hex: str
    height: Optional[int] = None
    uri: Optional[str] = None
    tag_hex: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"kind": self.kind, "message": self.message_hex}
        if self.height is not None:
            out["height"] = self.height
        if self.uri is not None:
            out["uri"] = self.uri
        if self.tag_hex:
            out["tag"] = self.tag_hex
        return out

    @property
    def block_merkle_root_display(self) -> str:
        """The attested Merkle root in block-explorer display order.

        Bitcoin serialises hashes little-endian internally and shows
        them big-endian. Esplora's ``merkle_root`` field and
        ``bitcoin-cli getblockheader`` both use display order, so a
        caller comparing against either needs this form.
        """
        return bytes.fromhex(self.message_hex)[::-1].hex()


@dataclasses.dataclass(frozen=True)
class OtsReceipt:
    """A parsed detached-timestamp file."""

    file_hash_op: str
    file_digest_hex: str
    attestations: Tuple[Attestation, ...]

    @property
    def bitcoin_attestations(self) -> Tuple[Attestation, ...]:
        return tuple(a for a in self.attestations if a.kind == "bitcoin")

    @property
    def pending_attestations(self) -> Tuple[Attestation, ...]:
        return tuple(a for a in self.attestations if a.kind == "pending")

    @property
    def heights(self) -> List[int]:
        """Bitcoin block heights named by the receipt, first-seen order."""
        seen: set[int] = set()
        out: List[int] = []
        for att in self.bitcoin_attestations:
            if att.height is None or att.height in seen:
                continue
            seen.add(att.height)
            out.append(att.height)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_hash_op": self.file_hash_op,
            "file_digest": self.file_digest_hex,
            "attestations": [a.to_dict() for a in self.attestations],
            "heights": self.heights,
        }


# ---------------------------------------------------------------------------
# Byte-stream reader
# ---------------------------------------------------------------------------


class _Reader:
    """Minimal sequential reader with the upstream varint encoding."""

    def __init__(self, blob: bytes) -> None:
        self._blob = blob
        self._pos = 0

    @property
    def remaining(self) -> int:
        return len(self._blob) - self._pos

    def read(self, n: int) -> bytes:
        if n < 0 or self.remaining < n:
            raise OtsParseError(
                f"truncated receipt: wanted {n} bytes at offset {self._pos}, "
                f"{self.remaining} left"
            )
        out = self._blob[self._pos : self._pos + n]
        self._pos += n
        return out

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_varuint(self) -> int:
        """Base-128 little-endian varint, as python-opentimestamps writes it."""
        value = 0
        shift = 0
        while True:
            byte = self.read_u8()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsParseError("varuint too long")

    def read_varbytes(self, max_len: int) -> bytes:
        length = self.read_varuint()
        if length > max_len:
            raise OtsParseError(
                f"varbytes length {length} exceeds limit {max_len}"
            )
        return self.read(length)


# ---------------------------------------------------------------------------
# Unary operations
# ---------------------------------------------------------------------------


def _ripemd160(data: bytes) -> bytes:
    try:
        h = hashlib.new("ripemd160")
    except ValueError as exc:  # OpenSSL 3 legacy provider disabled
        raise OtsParseError(
            "receipt uses RIPEMD-160 but this Python's hashlib has no "
            f"ripemd160 provider: {exc}"
        ) from exc
    h.update(data)
    return h.digest()


def _keccak256(data: bytes) -> bytes:
    raise OtsParseError(
        "receipt uses KECCAK-256, which stdlib hashlib does not provide "
        "(sha3_256 is the NIST variant, not Keccak); this branch cannot be "
        "walked offline"
    )


def _apply_op(reader: _Reader, tag: int, msg: bytes) -> bytes:
    """Apply one unary op to *msg*, consuming its operand if it has one."""
    if tag == 0xF0:  # append
        return msg + reader.read_varbytes(MAX_OPERAND_SIZE)
    if tag == 0xF1:  # prepend
        return reader.read_varbytes(MAX_OPERAND_SIZE) + msg
    if tag == 0xF2:  # reverse
        return msg[::-1]
    if tag == 0xF3:  # hexlify
        return binascii.hexlify(msg)
    if tag == 0x02:  # sha1
        return hashlib.sha1(msg).digest()  # noqa: S324 - format-mandated
    if tag == 0x03:  # ripemd160
        return _ripemd160(msg)
    if tag == 0x08:  # sha256
        return hashlib.sha256(msg).digest()
    if tag == 0x67:  # keccak256
        return _keccak256(msg)
    raise OtsParseError(f"unknown operation tag 0x{tag:02x}")


# ---------------------------------------------------------------------------
# Attestation and tree walk
# ---------------------------------------------------------------------------


def _read_attestation(reader: _Reader, msg: bytes) -> Attestation:
    tag = reader.read(8)
    payload = reader.read_varbytes(MAX_PAYLOAD_SIZE)
    inner = _Reader(payload)
    message_hex = msg.hex()
    tag_hex = tag.hex()

    if tag == TAG_BITCOIN:
        return Attestation(
            kind="bitcoin",
            message_hex=message_hex,
            height=inner.read_varuint(),
            tag_hex=tag_hex,
        )
    if tag == TAG_LITECOIN:
        return Attestation(
            kind="litecoin",
            message_hex=message_hex,
            height=inner.read_varuint(),
            tag_hex=tag_hex,
        )
    if tag == TAG_PENDING:
        uri = inner.read_varbytes(MAX_URI_LENGTH)
        return Attestation(
            kind="pending",
            message_hex=message_hex,
            uri=uri.decode("utf-8", errors="replace"),
            tag_hex=tag_hex,
        )
    if tag == TAG_ETHEREUM:
        return Attestation(
            kind="ethereum",
            message_hex=message_hex,
            height=inner.read_varuint(),
            tag_hex=tag_hex,
        )
    return Attestation(kind="unknown", message_hex=message_hex, tag_hex=tag_hex)


def _walk(reader: _Reader, msg: bytes, budget: List[int]) -> List[Attestation]:
    """Walk one timestamp node, returning every attestation beneath it.

    Iterative over the fork list, recursive over fork branches; the
    recursion depth is the number of *nested* forks, which the
    operation budget bounds.
    """
    found: List[Attestation] = []
    while True:
        budget[0] -= 1
        if budget[0] < 0:
            raise OtsParseError(
                f"receipt exceeds the {MAX_OPS}-operation walk budget"
            )
        tag = reader.read_u8()
        if tag == 0xFF:  # fork: this branch, then continue with the same msg
            inner_tag = reader.read_u8()
            if inner_tag == 0x00:
                found.append(_read_attestation(reader, msg))
            else:
                branch_msg = _apply_op(reader, inner_tag, msg)
                found.extend(_walk(reader, branch_msg, budget))
            continue
        if tag == 0x00:  # terminal attestation
            found.append(_read_attestation(reader, msg))
            return found
        msg = _apply_op(reader, tag, msg)


def parse_ots_receipt(blob: bytes) -> OtsReceipt:
    """Parse a detached ``.ots`` timestamp file.

    Raises
    ------
    OtsParseError
        On a missing magic header, an unsupported version, a truncated
        stream, an unknown opcode, or a receipt that blows the walk
        budget. Callers must treat the exception as "this is not a
        receipt I can check", never as "this is fine".
    """
    if not blob:
        raise OtsParseError("empty receipt")
    if not blob.startswith(OTS_MAGIC):
        raise OtsParseError("missing OpenTimestamps magic header")

    reader = _Reader(blob)
    reader.read(len(OTS_MAGIC))

    version = reader.read_varuint()
    if version != SUPPORTED_MAJOR_VERSION:
        raise OtsParseError(
            f"unsupported major version {version} "
            f"(this reader implements {SUPPORTED_MAJOR_VERSION})"
        )

    op_tag = reader.read_u8()
    if op_tag not in _FILE_HASH_OPS:
        raise OtsParseError(f"unknown file-hash op tag 0x{op_tag:02x}")
    op_name, digest_len = _FILE_HASH_OPS[op_tag]
    file_digest = reader.read(digest_len)

    attestations = _walk(reader, file_digest, [MAX_OPS])

    if reader.remaining:
        raise OtsParseError(
            f"{reader.remaining} trailing bytes after the proof tree"
        )

    return OtsReceipt(
        file_hash_op=op_name,
        file_digest_hex=file_digest.hex(),
        attestations=tuple(attestations),
    )


__all__ = [
    "Attestation",
    "OTS_MAGIC",
    "OtsParseError",
    "OtsReceipt",
    "parse_ots_receipt",
]
