# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Shared dataclasses for the external-verifier sub-package.

This module exists to break the import cycle between the pole
implementations (``poles.py``) and the aggregator (``aggregator.py``):
both need :class:`PoleResult`, and the aggregator additionally
imports the pole functions. Hoisting the dataclass into a leaf
module keeps the dependency graph one-way.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Mapping


@dataclasses.dataclass(frozen=True)
class PoleResult:
    """Outcome of running a single verification pole.

    See ``aggregator.PoleResult`` re-export for the documented
    public surface; this is the same dataclass.
    """

    name: str
    ok: bool
    verdict: str
    witness: Mapping[str, Any]
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "verdict": self.verdict,
            "witness": dict(self.witness),
            "note": self.note,
        }


__all__ = ["PoleResult"]
