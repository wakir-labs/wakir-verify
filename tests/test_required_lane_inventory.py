# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Callandor GmbH and contributors
"""What the required ``pytest (py3.13)`` lane actually executes.

A green tick proves the assertions that *ran*. It does not prove that
every test module was found. Three ways a module can leave the lane
without turning it red:

1. a **collection error** — pytest exits ``2`` for that, so this one is
   already loud; :func:`test_collect_only_reports_no_errors` pins the
   behaviour so it cannot be softened later (e.g. by
   ``--continue-on-collection-errors`` in ``addopts``);
2. an **import-time skip** — ``pytest.importorskip`` at module level
   turns a missing import into one skipped module. The lane stays green
   and the module's tests simply are not there;
3. a **guard inside a helper** — ``importorskip`` in a fixture or helper
   function skips the individual tests instead of the module. Quieter
   than (2) and just as effective at removing an assertion.

The documented occasion is this repository's own:
``tests/test_python_bitcoinlib_drift.py`` hung on ``importorskip`` from
the repo split until ADR-0074, and no lane installed the library, so the
one probe that compares against an independent third-party
implementation was skipped on every single run. It was found by hand.
This module is what makes the next occurrence loud instead.

Scope: this repository only. The lane is ``.github/workflows/ci.yml``
job ``test`` (display name ``pytest (py3.13)``), a required status check
on ``main``; it runs ``pytest tests/`` with no path filter, so "collected
by the lane" and "collected by ``pytest tests/``" are the same question.

Running this file in an environment without the lane's dependencies (a
dependency-free sandbox) fails on purpose: such an environment is not
the required lane and must not be mistaken for it.
"""

from __future__ import annotations

import ast
import functools
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
PYPROJECT = REPO_ROOT / "pyproject.toml"
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

#: Distribution name -> module name, for everything the required lane
#: installs. Every workflow in this repository that runs pytest installs
#: ``-e ".[test]"`` (pinned by
#: :func:`test_every_lane_that_runs_pytest_installs_the_test_extra`), so
#: the runtime dependencies *and* the ``test`` extra are equally present
#: — and a guard on any of them hides tests rather than adapting to a
#: leaner lane. Every entry of both lists must appear here, so adding a
#: dependency stays a visible decision.
LANE_DEPENDENCIES = {
    # [project].dependencies
    "rfc8785": "rfc8785",
    "requests": "requests",
    # [project.optional-dependencies].test
    "pytest": "pytest",
    "hypothesis": "hypothesis",
    "jsonschema": "jsonschema",
}

#: Import-time skip guards that are allowed, with the reason. Anything
#: named here is genuinely absent from *this* repository's required
#: lane. A guard on a lane dependency is not allowed: it hides tests
#: instead of failing.
ALLOWED_IMPORT_GUARDS = {
    "bitcoin": (
        "python-bitcoinlib is deliberately not a dependency of this package; "
        "it is installed only by .github/workflows/bitcoinlib-drift.yml, one "
        "pinned version per matrix job. That workflow asserts the probe is not "
        "skipped (JUnit tests==0 or skipped>0 fails the job), so the guard "
        "cannot go quiet the way it did before ADR-0074."
    ),
}

#: Modules that contribute no node id to the required lane, with the
#: mechanism that keeps them honest elsewhere. Not a general waiver:
#: :func:`test_guarded_module_contributes_when_its_import_is_available`
#: still requires the module to appear once the import exists.
MODULES_WITHOUT_NODE_IDS = {
    "tests/test_python_bitcoinlib_drift.py": (
        "guarded on 'bitcoin'; contributes in the bitcoinlib-drift matrix lane, "
        "which fails if the module skips there"
    ),
}


@functools.lru_cache(maxsize=1)
def _collect() -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q",
         "-p", "no:cacheprovider", "-o", "addopts="],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _node_ids_per_module() -> dict[str, int]:
    _, stdout, _ = _collect()
    counts: dict[str, int] = {}
    for line in stdout.splitlines():
        if "::" in line:
            module = line.split("::", 1)[0].strip()
            counts[module] = counts.get(module, 0) + 1
    return counts


def _test_modules() -> list[Path]:
    return sorted(TESTS_DIR.rglob("test_*.py"))


def _declared_dependencies() -> list[str]:
    """``[project].dependencies`` plus the ``test`` extra, without a TOML parser."""
    text = PYPROJECT.read_text(encoding="utf-8")
    names: list[str] = []
    for pattern in (r"^dependencies = \[(.*?)^\]", r"^test = \[(.*?)^\]"):
        block = re.search(pattern, text, re.MULTILINE | re.DOTALL)
        assert block, f"pyproject.toml has no block matching {pattern!r}"
        for raw in re.findall(r'"([^"]+)"', block.group(1)):
            names.append(re.split(r"[<>=!~\[ ]", raw, maxsplit=1)[0])
    assert names, "no dependency parsed from pyproject.toml"
    return names


def _import_guards(path: Path) -> list[tuple[str, int, bool]]:
    """Every ``pytest.importorskip`` in *path*: (module, line, module_level).

    Unlike a module-level-only scan, this also finds guards inside
    helpers and fixtures — failure mode (3) in the module docstring, and
    the shape two of this repository's four guards actually had.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    # Calls reachable from a module-level statement run at import time;
    # anything else runs per test or per fixture.
    module_level_calls = {
        id(node)
        for stmt in tree.body
        if isinstance(stmt, (ast.Expr, ast.Assign, ast.AnnAssign))
        for node in ast.walk(stmt)
    }
    found: list[tuple[str, int, bool]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "importorskip"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            found.append(
                (node.args[0].value, node.lineno, id(node) in module_level_calls)
            )
    return found


def test_collect_only_reports_no_errors() -> None:
    """A module that cannot be imported must fail the lane, not vanish.

    pytest exits ``2`` and appends ``, N errors`` to the summary line
    when a module fails to import. Both are asserted, so neither
    ``--continue-on-collection-errors`` nor a swallowed exit code can
    turn a missing module back into a green tick.
    """
    returncode, stdout, stderr = _collect()
    summary = [ln for ln in stdout.splitlines() if re.match(r"^\d+ tests? collected", ln)]
    assert summary, f"no collection summary line\n{stdout[-4000:]}"
    assert "error" not in summary[-1], summary[-1]
    reported_errors = [ln for ln in stdout.splitlines() if ln.startswith("ERROR ")]
    assert not reported_errors, reported_errors
    assert returncode == 0, f"exit {returncode}\n{stdout[-4000:]}\n{stderr[-2000:]}"


def test_every_test_module_contributes_at_least_one_node_id() -> None:
    """No module may leave the lane silently."""
    counts = _node_ids_per_module()
    empty = []
    for path in _test_modules():
        rel = str(path.relative_to(REPO_ROOT))
        if counts.get(rel, 0) == 0 and rel not in MODULES_WITHOUT_NODE_IDS:
            empty.append(rel)
    assert not empty, (
        "these modules collected nothing — an import-time skip or an empty "
        f"module, either way their assertions did not run: {empty}"
    )


def test_collected_node_id_total_is_the_sum_of_the_modules() -> None:
    """Guards against a parse that silently loses node ids."""
    counts = _node_ids_per_module()
    _, stdout, _ = _collect()
    reported = re.search(r"^(\d+) tests? collected", stdout, re.MULTILINE)
    assert reported, stdout[-2000:]
    assert sum(counts.values()) == int(reported.group(1))
    # Every module that contributed must be a known test module, and the
    # only ones allowed to be absent are the recorded guarded ones. A
    # fixed count would be wrong here: in the bitcoinlib-drift lane the
    # guarded module *does* contribute, and this test runs there too.
    known = {str(p.relative_to(REPO_ROOT)) for p in _test_modules()}
    assert set(counts) <= known, sorted(set(counts) - known)
    assert known - set(counts) <= set(MODULES_WITHOUT_NODE_IDS), sorted(
        known - set(counts) - set(MODULES_WITHOUT_NODE_IDS)
    )


@pytest.mark.parametrize("dependency", _declared_dependencies())
def test_lane_dependencies_are_importable(dependency: str) -> None:
    """Turn a silently skipped module into one loud failure.

    Every pytest lane here installs ``.[test]``. If the environment
    lacks one of those distributions, modules would skip at import time
    and the tick would stay green. Here it does not.
    """
    assert dependency in LANE_DEPENDENCIES, (
        f"new dependency {dependency!r}: add its import name to LANE_DEPENDENCIES "
        "so the lane keeps checking that it is really installed"
    )
    # Deliberately __import__, never pytest.importorskip: a missing lane
    # dependency has to fail, not skip.
    __import__(LANE_DEPENDENCIES[dependency])


def test_import_guards_are_on_non_lane_imports_only() -> None:
    """A guard on a lane dependency hides tests instead of failing.

    Checked at any nesting depth: two of this repository's guards sat in
    a helper function, where they removed individual tests rather than a
    whole module — quieter, same effect.
    """
    lane_modules = set(LANE_DEPENDENCIES.values())
    offenders: dict[str, list[str]] = {}
    for path in _test_modules():
        bad = [
            f"{module} (line {lineno}, "
            f"{'module level' if top else 'inside a function'})"
            for module, lineno, top in _import_guards(path)
            if module.split(".")[0] in lane_modules
        ]
        if bad:
            offenders[str(path.relative_to(REPO_ROOT))] = bad
    assert not offenders, (
        "pytest.importorskip on a dependency the required lane installs: these "
        "tests vanish from a green tick. Import it plainly instead — if it is "
        "genuinely optional, drop it from pyproject.toml and record it in "
        f"ALLOWED_IMPORT_GUARDS with a reason: {offenders}"
    )


def test_every_import_guard_has_a_recorded_reason() -> None:
    """An unexplained guard is an undated exception."""
    undocumented: dict[str, list[str]] = {}
    for path in _test_modules():
        bad = [
            module for module, _lineno, _top in _import_guards(path)
            if module.split(".")[0] not in ALLOWED_IMPORT_GUARDS
        ]
        if bad:
            undocumented[str(path.relative_to(REPO_ROOT))] = bad
    assert not undocumented, (
        "pytest.importorskip on a module with no entry in "
        "ALLOWED_IMPORT_GUARDS. Record why the import may be absent from "
        "the required lane, and which lane covers it instead: "
        f"{undocumented}"
    )


def test_guarded_module_contributes_when_its_import_is_available() -> None:
    """The allowance in MODULES_WITHOUT_NODE_IDS is conditional, not blanket.

    In the bitcoinlib-drift matrix lane ``bitcoin`` is installed, and
    there the module must collect. Without it, the entry would let the
    drift probe disappear from *every* lane again.
    """
    counts = _node_ids_per_module()
    for rel, _reason in MODULES_WITHOUT_NODE_IDS.items():
        guards = _import_guards(REPO_ROOT / rel)
        assert guards, f"{rel} is listed as guarded but has no importorskip"
        available = []
        for module, _lineno, _top in guards:
            try:
                __import__(module)
            except ImportError:
                continue
            available.append(module)
        if available:
            assert counts.get(rel, 0) > 0, (
                f"{rel} collected nothing although {available} imported fine — "
                "the module is skipping for some other reason and its "
                "assertions are not running anywhere"
            )


def test_every_lane_that_runs_pytest_installs_the_test_extra() -> None:
    """The premise under LANE_DEPENDENCIES and under the removed guards.

    If a lane ran pytest without ``.[test]``, ``hypothesis`` and
    ``jsonschema`` would genuinely be absent there and importing them
    plainly would be wrong. This keeps that premise true rather than
    assumed.
    """
    invocation = re.compile(r"(^|\s)(python -m pytest|pytest)\s")
    missing: dict[str, str] = {}
    for workflow in sorted(WORKFLOW_DIR.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        runs_pytest = any(
            invocation.search(line) and "pip install" not in line
            and not line.lstrip().startswith("#")
            for line in text.splitlines()
        )
        if runs_pytest and '".[test]"' not in text:
            missing[workflow.name] = "runs pytest without installing the test extra"
    assert not missing, (
        "these lanes run pytest without installing '.[test]'; the plain "
        "imports of hypothesis/jsonschema in the suite would fail there. "
        "Either install the extra or restore a documented guard: "
        f"{missing}"
    )
