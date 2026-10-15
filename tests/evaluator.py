#!/usr/bin/env python3
"""
A small, dependency-light Sigma evaluator.

This is NOT a full Sigma backend. It implements exactly the subset of the Sigma
spec these rules use, so the detection logic can be unit-tested against sample log
events in CI: "does the rule fire on the malicious event, and stay silent on the
benign one?". Supported: string/number equality, value lists (OR), the
`contains` / `startswith` / `endswith` / `re` value modifiers, the `all` combinator,
map-lists (OR of maps), dotted field paths, and conditions built from
`and` / `or` / `not`, parentheses, and `1 of` / `all of <pattern|them>`.

String matching is case-insensitive, matching the default behaviour of common
Sigma backends.
"""
from __future__ import annotations

import fnmatch
import json
import re


def _get(event: dict, field: str):
    """Resolve a (possibly dotted) field path out of an event dict."""
    cur = event
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _stringify(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v)


def _match_scalar(event_val, expected, modifier: str | None) -> bool:
    exp = str(expected).lower()
    if modifier in ("contains", "startswith", "endswith"):
        hay = _stringify(event_val).lower()
        if modifier == "contains":
            return exp in hay
        if modifier == "startswith":
            return hay.startswith(exp)
        return hay.endswith(exp)
    if modifier == "re":
        return re.search(str(expected), _stringify(event_val)) is not None
    # default: equality (lists in the event match if any element equals)
    if isinstance(event_val, list):
        return any(str(x).lower() == exp for x in event_val)
    return _stringify(event_val).lower() == exp


def _match_field(event: dict, key: str, expected) -> bool:
    parts = key.split("|")
    field = parts[0]
    mods = parts[1:]
    all_mod = "all" in mods
    scalar_mod = next((m for m in mods if m in ("contains", "startswith", "endswith", "re")), None)
    ev = _get(event, field)
    expected_list = expected if isinstance(expected, list) else [expected]
    results = [_match_scalar(ev, e, scalar_mod) for e in expected_list]
    return all(results) if all_mod else any(results)


def _match_selection(event: dict, selection) -> bool:
    if isinstance(selection, list):  # list of maps => OR
        return any(_match_selection(event, s) for s in selection)
    return all(_match_field(event, k, v) for k, v in selection.items())


def _eval_condition(cond: str, truth: dict[str, bool]) -> bool:
    expr = cond.strip()

    def expand(m: re.Match) -> str:
        qty, patt = m.group(1), m.group(2)
        names = list(truth) if patt == "them" else [n for n in truth if fnmatch.fnmatch(n, patt)]
        vals = [str(truth[n]) for n in names]
        if qty == "all":
            return "(" + " and ".join(["True", *vals]) + ")"
        return "(" + " or ".join(["False", *vals]) + ")"

    expr = re.sub(r"\b(all|1)\s+of\s+([A-Za-z0-9_\*]+|them)", expand, expr)

    def repl(m: re.Match) -> str:
        n = m.group(0)
        if n in ("and", "or", "not", "True", "False"):
            return n
        return str(truth[n]) if n in truth else n

    expr = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", repl, expr)
    return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - trusted rule input


def evaluate(rule: dict, event: dict) -> bool:
    """Return True if the rule's detection condition matches the event."""
    det = rule["detection"]
    selections = {k: v for k, v in det.items() if k != "condition"}
    truth = {name: _match_selection(event, val) for name, val in selections.items()}
    return _eval_condition(det["condition"], truth)
