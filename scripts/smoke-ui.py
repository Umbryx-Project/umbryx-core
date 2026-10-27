#!/usr/bin/env python3
"""UI smoke suite over the demo stand (track C, 2026-10-09).

    scripts/smoke-ui.py --edition ce --url http://localhost:8898

Formalises what scripts/capture-screenshots.py already knows how to reach —
login, tab registry, project selection — into assertions instead of frames.
Every documented screen must:

  * mount (no error-boundary "Umbryx — rendering error", #root populated),
  * produce zero uncaught JS exceptions,
  * produce zero console.error messages,
  * issue zero HTTP responses with status >= 500.

The suite is deliberately dumb about content: the backend suite owns data
correctness, this one owns "the screen is alive after a build". It refuses
the live instance and checks the stand's edition, exactly like the capture
script, and it reuses the stand raised by scripts/demo-stand.sh.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from playwright.sync_api import TimeoutError as PWTimeout
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - a setup problem, not a run problem
    sys.exit(
        "playwright is not installed. See the module docstring:\n"
        "  python3 -m venv .venv && .venv/bin/pip install playwright\n"
        "  .venv/bin/python -m playwright install chromium"
    )

# Tab registry mirrors capture-screenshots.py; (name-for-humans, tab id,
# needs project[, edition it exists in]).
TABS = [
    ("projects", "projects", False),
    ("network", "network", True),
    ("hosts", "hosts", True),
    ("creds", "creds", True),
    ("findings", "findings", True),
    ("notes", "notes", True),
    ("loot", "loot", True),
    ("kb", "kb", True),
    ("jobs", "jobs", True),
    ("objectives", "objectives", True),
    ("attackpath", "attackpath", True),
    ("scope", "scope", True),
    ("attackgraph", "attackgraph", True),
    ("report", "report", True),
    ("timeline", "timeline", True),
    ("scans", "scans", True),
    ("playbooks", "playbooks", True),
    ("automations", "automations", True),
    ("cheatsheet", "cheatsheet", True),
    ("platform-ops", "platform-ops", True, "ee"),
    ("workstations", "workstations", True),
    ("roe", "roe", True),
    ("checklist", "checklist", True),
    ("admin", "admin", False),
]


def api(base: str, path: str, cookie: str = "") -> dict:
    req = urllib.request.Request(f"{base}{path}")
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def fail(msg: str) -> int:
    print(f"FAIL: {msg}")
    return 1


class ScreenWatch:
    """Collect JS/page/network failure signals for one screen."""

    def __init__(self, page):
        self.page_errors: list[str] = []
        self.console_errors: list[str] = []
        self.http_5xx: list[str] = []
        page.on("pageerror", lambda e: self.page_errors.append(str(e)))
        page.on(
            "console",
            lambda m: self.console_errors.append(m.text[:200])
            if m.type == "error"
            else None,
        )
        page.on(
            "response",
            lambda r: self.http_5xx.append(f"{r.status} {r.url[:120]}")
            if r.status >= 500
            else None,
        )

    def reset(self) -> None:
        self.page_errors.clear()
        self.console_errors.clear()
        self.http_5xx.clear()


def settle(page, deadline_s: float = 8.0) -> None:
    """Same contract as capture-screenshots.py: quiet network, no Loading."""
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        remaining_ms = max(500, int((end - time.monotonic()) * 1000))
        try:
            page.wait_for_load_state("networkidle", timeout=remaining_ms)
        except PWTimeout:
            break
        if page.locator("text=/Loading[ .…]/i").count() == 0:
            break
        time.sleep(0.5)
    time.sleep(0.4)


def check_mounted(page) -> str | None:
    """Return a failure reason when the screen did not mount."""
    if page.locator("text=Umbryx — rendering error").count():
        return f"error boundary: {page.inner_text('body')[:150]}"
    root_children = page.eval_on_selector_all(
        "#root > *", "els => els.length"
    )
    if not root_children:
        return "#root is empty"
    text_len = page.eval_on_selector("#root", "el => el.innerText.length")
    if text_len < 30:
        return f"#root rendered only {text_len} chars — blank screen?"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="http://localhost:8899", help="demo stand base URL")
    ap.add_argument("--edition", required=True, choices=["ce", "ee"])
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="Demo2024!")
    ap.add_argument("--project", default="", help="project id (default: first active)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    if ":8888" in base:
        return fail("port 8888 is the live instance — smoke the demo stand")

    try:
        status = api(base, "/api/auth/status")
    except (urllib.error.URLError, TimeoutError) as exc:
        return fail(f"{base} is not answering: {exc}")
    if not status.get("initialized"):
        return fail("stand has no users — run scripts/demo-stand.sh up first")

    results: list[tuple[str, str | None]] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        page = ctx.new_page()
        watch = ScreenWatch(page)

        # 1) login screen + the login flow itself
        watch.reset()
        page.goto(f"{base}/", wait_until="networkidle")
        settle(page)
        reason = check_mounted(page) or (
            "login form missing"
            if not page.locator('button:has-text("Sign in")').count()
            else None
        )
        page.fill('input[placeholder="username"]', args.user)
        page.fill('input[type=password]', args.password)
        page.click('button:has-text("Sign in")')
        try:
            page.wait_for_selector('input[placeholder="username"]', state="detached", timeout=20000)
        except PWTimeout:
            browser.close()
            return fail("login did not go through — check the credentials")
        settle(page)
        results.append(("login", reason))

        cookie = "; ".join(f"{c['name']}={c['value']}" for c in ctx.cookies())
        edition = api(base, "/api/system/edition", cookie)
        if edition.get("edition") != args.edition:
            browser.close()
            return fail(
                f"stand reports edition {edition.get('edition')!r}, run was told {args.edition!r}"
            )
        print(f"edition={edition['edition']} tier={edition.get('tier')}")

        pid = args.project
        if not pid:
            projects = api(base, "/api/projects", cookie)
            items = projects if isinstance(projects, list) else projects.get("items", [])
            active = [p for p in items if p.get("status") == "active"]
            if not active:
                browser.close()
                return fail("stand has no active project — is it seeded?")
            pid = active[0]["id"]
        page.evaluate("pid => localStorage.setItem('rt_project', pid)", pid)
        print(f"project={pid}")

        # 2) every tab
        for entry in TABS:
            name, tab, _needs_project = entry[:3]
            only_in = entry[3] if len(entry) > 3 else None
            if only_in and only_in != args.edition:
                results.append((name + " [not in this edition]", None))
                continue
            watch.reset()
            page.goto(f"{base}/#{tab}", wait_until="domcontentloaded")
            settle(page)
            if name == "hosts":
                row = page.locator('[id^="host-"]').first
                if row.count():
                    row.click()
                    settle(page)
            reason = check_mounted(page)
            if watch.page_errors:
                reason = reason or "page errors"
                reason = f"{reason}; pageerror: {watch.page_errors[0]}" if reason else f"pageerror: {watch.page_errors[0]}"
            if watch.console_errors:
                reason = f"{reason}; console.error: {watch.console_errors[0]}" if reason else f"console.error: {watch.console_errors[0]}"
            if watch.http_5xx:
                reason = f"{reason}; http 5xx: {watch.http_5xx[0]}" if reason else f"http 5xx: {watch.http_5xx[0]}"
            results.append((name, reason))

        # 3) the Ctrl+K search overlay
        watch.reset()
        page.goto(f"{base}/#kb", wait_until="domcontentloaded")
        settle(page)
        page.keyboard.press("Control+k")
        page.wait_for_timeout(400)
        page.keyboard.type("admin", delay=30)
        settle(page)
        overlay_present = page.locator('input[placeholder*="earch"], input[aria-label*="earch"]').count()
        reason = None if overlay_present else "search overlay did not open"
        results.append(("search-overlay", reason))

        browser.close()

    failures = [(n, r) for n, r in results if r]
    for name, reason in results:
        mark = "PASS" if not reason else "FAIL"
        suffix = f" — {reason}" if reason else ""
        print(f"  {mark}  {name}{suffix}")
    print(f"\n{len(results) - len(failures)}/{len(results)} screens passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
