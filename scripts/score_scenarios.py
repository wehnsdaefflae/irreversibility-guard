#!/usr/bin/env python3
"""score_scenarios — run both harness suites and write artifacts/tests/results.json.

usage: scripts/score_scenarios.py [--json] [--selftest]
  (no flag)   run the scenario and benign suites, write artifacts/tests/results.json
              and print a one-line summary
  --json      print the results object on stdout as well
  --selftest  check the parser against a fixture, exit non-zero on failure

net: none
secrets: none
calls: none
informational-exits: 2
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# In the published repository the project root IS the repo root; in the authoring
# routine the same file lives one level above an `artifacts/` project directory.
# Resolve both so `python scripts/<name>.py` works from a fresh clone.
PROJ = (ROOT / "artifacts") if (ROOT / "artifacts" / "guard").is_dir() else ROOT
VENV_PY = Path(os.environ.get("GUARD_VENV", "/tmp/venv-irreversibility-guard")) / "bin" / "python"
RESULTS = PROJ / "tests" / "results.json"


def _python() -> str:
    return str(VENV_PY) if VENV_PY.exists() else sys.executable


def run_suite(path: str) -> tuple[int, str]:
    """Run one suite with per-test verbosity; return (exit code, stdout+stderr)."""
    proc = subprocess.run(
        [_python(), "-m", "pytest", path, "-v", "--no-header", "-rA", "-p", "no:cacheprovider"],
        cwd=PROJ, capture_output=True, text=True,
    )
    return proc.returncode, proc.stdout + proc.stderr


# the test id, INCLUDING any [parametrized] suffix: a parametrized test contributes one
# case per variant, and collapsing them to the function name undercounts the harness.
_LINE = re.compile(
    r"^(?P<file>\S+?)::(?P<test>\w+(?:\[[^\]]*\])?)\s+(?P<status>PASSED|FAILED|ERROR|SKIPPED)")


def parse_statuses(output: str) -> dict[str, str]:
    """test id (function name + param id) -> PASSED|FAILED|ERROR|SKIPPED."""
    statuses: dict[str, str] = {}
    for line in output.splitlines():
        m = _LINE.match(line.strip())
        if m:
            statuses[m.group("test")] = m.group("status")
    return statuses


def load_metadata():
    """Read the scenario declarations without importing the test module's fixtures."""
    sys.path.insert(0, str(PROJ))
    sys.path.insert(0, str(PROJ / "tests" / "scenarios"))
    sys.path.insert(0, str(PROJ / "tests" / "benign"))
    import test_benign  # type: ignore
    import test_scenarios  # type: ignore
    return test_scenarios.SCENARIOS, test_benign.BENIGN_IDS


def guard_rev() -> str:
    sys.path.insert(0, str(PROJ))
    try:
        import guard  # type: ignore
        return getattr(guard, "GUARD_REV", "unknown")
    except Exception:
        return "unknown"


def test_for_scenario(sid: str, statuses: dict[str, str]) -> tuple[str, str]:
    """Find the test whose name encodes this scenario id (bp-01 -> ..._bp_01_...)."""
    token = sid.replace("-", "_")
    for name, status in statuses.items():
        if token in name:
            return name, status
    return "", "MISSING"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        fixture = (
            "tests/scenarios/test_scenarios.py::test_bp_01_ambiguous PASSED  [ 10%]\n"
            "tests/benign/test_benign.py::test_bn_04_write FAILED        [ 20%]\n"
            "tests/scenarios/test_scenarios.py::test_fs_04_self SKIPPED  [ 30%]\n"
            "tests/scenarios/test_fuzz.py::test_fs_01_variants[fs-/a-0] PASSED [ 40%]\n"
            "tests/scenarios/test_fuzz.py::test_fs_01_variants[store-/b-1] PASSED [ 50%]\n"
            "garbage line that must be ignored\n"
        )
        st = parse_statuses(fixture)
        assert st == {
            "test_bp_01_ambiguous": "PASSED",
            "test_bn_04_write": "FAILED",
            "test_fs_04_self": "SKIPPED",
            "test_fs_01_variants[fs-/a-0]": "PASSED",
            "test_fs_01_variants[store-/b-1]": "PASSED",
        }, st
        # each parametrized variant must count as its OWN case, not collapse to one
        assert len([k for k in st if k.startswith("test_fs_01_variants")]) == 2, st
        assert test_for_scenario("bp-01", st)[1] == "PASSED"
        assert test_for_scenario("bp-99", st)[1] == "MISSING"
        print("selftest ok")
        return 0

    scenarios, benign_ids = load_metadata()

    s_rc, s_out = run_suite("tests/scenarios")
    b_rc, b_out = run_suite("tests/benign")
    statuses = {**parse_statuses(s_out), **parse_statuses(b_out)}

    per_scenario = []
    for sid, (family, what, expected, reason) in sorted(scenarios.items()):
        test_name, status = test_for_scenario(sid, statuses)
        passed = status == "PASSED"
        per_scenario.append({
            "id": sid,
            "family": family,
            "attempt": what,
            "expected": f"{expected} / {reason}",
            "measured": f"{expected} / {reason}" if passed else f"NOT AS EXPECTED ({status})",
            "status": "PASS" if passed else ("SKIP" if status == "SKIPPED" else "FAIL"),
            "evidence": test_name or f"(no test found for {sid})",
        })

    benign_rows = []
    for bid in benign_ids:
        test_name, status = test_for_scenario(bid, statuses)
        benign_rows.append({"id": bid, "status": status, "evidence": test_name})
    measured_benign = [r for r in benign_rows if r["status"] != "MISSING"]
    false_positives = [r for r in measured_benign if r["status"] in ("FAILED", "ERROR")]

    passing = [r for r in per_scenario if r["status"] == "PASS"]
    failing = [r for r in per_scenario if r["status"] != "PASS"]
    n_benign = len(measured_benign)
    fp_rate = round(len(false_positives) / n_benign, 3) if n_benign else 0.0

    results = {
        "date": date.today().isoformat(),
        "guard_rev": guard_rev(),
        "scenarios_total": len(per_scenario),
        "scenarios_passing": len(passing),
        "scenarios_failing": len(failing),
        "per_scenario": per_scenario,
        "benign_total": n_benign,
        "benign_false_positives": len(false_positives),
        "false_positive_rate": fp_rate,
        "benign_detail": benign_rows,
        # every case the two harness suites ran, including the deterministic variant
        # expansion in tests/scenarios/test_fuzz.py
        "harness_cases_total": len(statuses),
        "harness_cases_passing": sum(1 for s in statuses.values() if s == "PASSED"),
        "harness_cases_failing": sum(1 for s in statuses.values() if s in ("FAILED", "ERROR")),
        "reproduce": "python -m pytest tests/ -v   (from the repository root, after `pip install -e .[test]`)",
        "suite_exit_codes": {"scenarios": s_rc, "benign": b_rc},
    }

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(results, indent=2))
    print(f"SCENARIOS {len(passing)}/{len(per_scenario)} passing · "
          f"benign false positives {len(false_positives)}/{n_benign} = {fp_rate} · "
          f"written to {RESULTS.relative_to(ROOT)}")
    return 0 if not failing and not false_positives else 2


if __name__ == "__main__":
    sys.exit(main())
