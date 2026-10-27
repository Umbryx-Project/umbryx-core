"""Validate .gitlab-ci.yml beyond YAML syntax: every `script`, `before_script`
and `after_script` item must be a plain string.

YAML happily parses `echo "failed for: x"` inside a plain scalar as a
MAPPING (colon+space is a key separator) — valid YAML, but GitLab's job
schema rejects it with the cryptic "script config should be a string or
a nested array of strings". Found live 2026-10-25; this check makes the
whole class impossible to merge again.

Usage: python3 scripts/check_ci_yaml.py [.gitlab-ci.yml …]
"""

from __future__ import annotations

import sys

import yaml

KEYS = ("script", "before_script", "after_script")


def check(path: str) -> list[str]:
    problems: list[str] = []
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict):
        return [f"{path}: not a mapping"]
    for job, spec in doc.items():
        if job in ("stages", "variables", "workflow", "include") or not isinstance(spec, dict):
            continue
        if "script" not in spec and "before_script" not in spec and "after_script" not in spec:
            continue
        for key in KEYS:
            val = spec.get(key)
            if val is None:
                continue
            items = val if isinstance(val, list) else [val]
            for i, item in enumerate(items):
                if not isinstance(item, str):
                    problems.append(
                        f"{path}: job '{job}' {key}[{i}] is {type(item).__name__}, not a string "
                        f"→ GitLab will reject the pipeline (colon+space in a plain scalar?)"
                    )
    return problems


def main() -> int:
    paths = sys.argv[1:] or [".gitlab-ci.yml"]
    problems: list[str] = []
    for p in paths:
        problems.extend(check(p))
    for msg in problems:
        print(f"ERROR {msg}")
    if not problems:
        print(f"OK: {', '.join(paths)} — all script items are strings")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
