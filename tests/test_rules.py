#!/usr/bin/env python3
"""
Detection unit tests. For every rule in ../rules, load its true-positive and benign
log fixtures from ./logs and assert the rule fires on every malicious event and stays
silent on every benign event.

Run directly:   python tests/test_rules.py      (prints a table, exits non-zero on failure)
Run via pytest: pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluator import evaluate  # noqa: E402

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
LOGS_DIR = Path(__file__).resolve().parent / "logs"


def _load_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text())


def _cases():
    for rule_path in sorted(RULES_DIR.glob("*.yml")):
        rule = yaml.safe_load(rule_path.read_text())
        stem = rule_path.stem
        tp = _load_events(LOGS_DIR / f"{stem}.tp.json")
        benign = _load_events(LOGS_DIR / f"{stem}.benign.json")
        yield stem, rule, tp, benign


def check_rule(rule: dict, tp: list[dict], benign: list[dict]) -> list[str]:
    """Return a list of failure messages (empty == pass)."""
    failures = []
    for i, ev in enumerate(tp):
        if not evaluate(rule, ev):
            failures.append(f"  MISS  true-positive event #{i} did NOT fire: {ev.get('_comment', ev)}")
    for i, ev in enumerate(benign):
        if evaluate(rule, ev):
            failures.append(f"  FP    benign event #{i} fired (false positive): {ev.get('_comment', ev)}")
    return failures


# ---- pytest entry point -------------------------------------------------------
def test_all_rules():
    problems = []
    for stem, rule, tp, benign in _cases():
        assert tp, f"{stem}: no true-positive fixtures found"
        assert benign, f"{stem}: no benign fixtures found"
        problems += [f"{stem}: {f}" for f in check_rule(rule, tp, benign)]
    assert not problems, "\n" + "\n".join(problems)


# ---- standalone runner --------------------------------------------------------
def main() -> int:
    total_fail = 0
    print(f"{'RULE':<52} {'TP':>3} {'BENIGN':>7}  RESULT")
    print("-" * 80)
    for stem, rule, tp, benign in _cases():
        fails = check_rule(rule, tp, benign)
        status = "PASS" if not fails else "FAIL"
        total_fail += len(fails)
        print(f"{stem:<52} {len(tp):>3} {len(benign):>7}  {status}")
        for line in fails:
            print(line)
    print("-" * 80)
    print("ALL TESTS PASSED" if total_fail == 0 else f"{total_fail} CHECK(S) FAILED")
    return 1 if total_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
