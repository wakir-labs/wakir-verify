# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Stdlib-only Bitcoin block header decoder for offline verification.

A Bitcoin block header is exactly 80 bytes, little-endian, with the
following layout (Bitcoin Core / BIP convention):

==  ================  ====================================
Off Field             Bytes
==  ================  ====================================
0   version            4
4   prev_block_hash    32 (little-endian internal byte order)
36  merkle_root        32 (little-endian internal byte order)
68  time               4
72  bits               4 (compact difficulty target)
76  nonce              4
==  ================  ====================================

The *canonical* block hash that appears in human-facing UIs and in
public Bitcoin explorers is ``sha256(sha256(header_bytes))`` read in
**reverse byte order** (display endianness).

This module is intentionally stdlib-only: no third-party Bitcoin
library dependency. The verifier needs to be auditable byte-by-byte
by anyone who can read 200 lines of Python.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Final


BITCOIN_HEADER_LENGTH: Final[int] = 80


class BitcoinHeaderParseError(ValueError):
    """Raised when a byte buffer is not a valid 80-byte block header."""


@dataclasses.dataclass(frozen=True)
class BitcoinBlockHeader:
    """Decoded Bitcoin block header."""

    version: int
    prev_block_hash_internal: bytes  # 32 bytes, little-endian internal
    merkle_root_internal: bytes      # 32 bytes, little-endian internal
    time: int
    bits: int
    nonce: int
    raw: bytes

    @property
    def prev_block_hash_display(self) -> str:
        """Big-endian display hex (reverse of internal byte order)."""
        return self.prev_block_hash_internal[::-1].hex()

    @property
    def merkle_root_display(self) -> str:
        return self.merkle_root_internal[::-1].hex()

    @property
    def block_hash_display(self) -> str:
        """Canonical big-endian display hash (sha256d, byte-reversed)."""
        return compute_block_hash_display(self.raw)


def parse_block_header(buf: bytes) -> BitcoinBlockHeader:
    """Parse an 80-byte little-endian block header.

    Raises :class:`BitcoinHeaderParseError` if *buf* is not exactly
    80 bytes long.
    """
    if not isinstance(buf, (bytes, bytearray)):
        raise BitcoinHeaderParseError(
            f"header buffer must be bytes-like, got {type(buf).__name__}"
        )
    if len(buf) != BITCOIN_HEADER_LENGTH:
        raise BitcoinHeaderParseError(
            f"header buffer must be exactly {BITCOIN_HEADER_LENGTH} "
            f"bytes, got {len(buf)}"
        )
    raw = bytes(buf)
    version = int.from_bytes(raw[0:4], "little")
    prev_block = raw[4:36]
    merkle_root = raw[36:68]
    time_val = int.from_bytes(raw[68:72], "little")
    bits = int.from_bytes(raw[72:76], "little")
    nonce = int.from_bytes(raw[76:80], "little")
    return BitcoinBlockHeader(
        version=version,
        prev_block_hash_internal=prev_block,
        merkle_root_internal=merkle_root,
        time=time_val,
        bits=bits,
        nonce=nonce,
        raw=raw,
    )


def compute_block_hash_display(header_bytes: bytes) -> str:
    """Compute the canonical big-endian display block hash.

    The hash is ``sha256(sha256(header))`` read in reverse byte order.
    Matches the hash shown by every public Bitcoin block explorer.
    """
    if len(header_bytes) != BITCOIN_HEADER_LENGTH:
        raise BitcoinHeaderParseError(
            f"header must be {BITCOIN_HEADER_LENGTH} bytes to hash, "
            f"got {len(header_bytes)}"
        )
    first = hashlib.sha256(header_bytes).digest()
    second = hashlib.sha256(first).digest()
    return second[::-1].hex()


__all__ = [
    "BITCOIN_HEADER_LENGTH",
    "BitcoinHeaderParseError",
    "BitcoinBlockHeader",
    "parse_block_header",
    "compute_block_hash_display",
]
