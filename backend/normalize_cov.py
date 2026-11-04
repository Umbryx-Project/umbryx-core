"""Normalize the container's coverage.xml for the SonarQube scanner.

Run INSIDE the test container (cwd=/app), right after pytest-cov writes
coverage.xml. Found live, twice:

1. coverage.py writes MULTIPLE <source> roots (or the container's
   /app/app). SonarQube 26 rejects every class path that resolves in
   more than one source ("ambiguity — the file exists in several
   'source'") and attaches ZERO python coverage, so the quality gate
   judges the whole backend uncovered.
2. The runner's Alpine BusyBox sed cannot be trusted for this either
   (\\t is not interpreted, and the container emits filenames relative
   to /app/app — WITHOUT the app/ prefix — so a `filename="app/…`
   rewrite matches nothing and silently drops python coverage again).

This script is format-agnostic: it collapses <sources> to a single
project-root source and rewrites every class filename to the repo
layout the scanner runs from (backend/app/…), handling both the
container's `core/x.py` and a local run's `app/core/x.py` shapes.
"""

from __future__ import annotations

import re

REPORT = "coverage.xml"
PREFIX = "backend/"


def _fix_filename(match: re.Match) -> str:
    fname = match.group(1)
    if fname.startswith(PREFIX) or fname.startswith(("/", "tests/", "alembic/", "modules/")):
        return match.group(0)
    if fname.startswith("app/"):
        return f'filename="{PREFIX}{fname}"'
    return f'filename="{PREFIX}app/{fname}"'


def main() -> None:
    with open(REPORT) as fh:
        data = fh.read()
    data = re.sub(
        r"<sources>.*?</sources>",
        "<sources><source>.</source></sources>",
        data,
        count=1,
        flags=re.S,
    )
    data = re.sub(r'filename="([^"]+)"', _fix_filename, data)
    with open(REPORT, "w") as fh:
        fh.write(data)


if __name__ == "__main__":
    main()
