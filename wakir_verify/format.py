# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors

"""Output formatting helpers for ``wakir-verify`` CLI.

Two output surfaces:

- ``json`` — machine-readable, pipeable to ``jq``. Default.
- ``text`` — human-readable, brand-demo + auditor-readable.

Currently the CLI ``wakir_verify.cli`` carries its own renderer
functions (``_render_verification_text`` etc.) inline; this module
exposes a thin re-export so external code can call a stable formatter
surface without depending on the CLI internals.
"""

from __future__ import annotations

import json
from typing import Any, Mapping


def format_json(payload: Mapping[str, Any], *, indent: int = 2) -> str:
    """Render *payload* as a deterministic JSON string.

    Uses ``sort_keys=True`` so the textual output is stable across
    Python versions and dict ordering. The ``indent`` default of 2
    matches the Wakir audit-report norm.
    """
    return json.dumps(dict(payload), sort_keys=True, indent=indent)


def format_text_verification(verification: Any) -> str:
    """Render an :class:`AnchorVerification` as human-readable text.

    Re-exported from :mod:`wakir_verify.cli` to give external callers
    a stable surface independent of CLI internals.
    """
    from wakir_verify.cli import _render_verification_text

    return _render_verification_text(verification)


def format_text_pole(pole_result: Any) -> str:
    """Render a single :class:`PoleResult` as human-readable text."""
    from wakir_verify.cli import _render_pole_text

    return _render_pole_text(pole_result)


__all__ = [
    "format_json",
    "format_text_verification",
    "format_text_pole",
]
