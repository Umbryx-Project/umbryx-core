#!/usr/bin/env python3
"""Capture the documentation screenshots from a seeded demo stand.

    scripts/capture-screenshots.py --edition ee --out docs/screenshots/ee
    scripts/capture-screenshots.py --edition ce --out docs/screenshots/ce \
        --url http://localhost:8898

Point it at a stand raised by scripts/demo-stand.sh and seeded by
backend/scripts/seed_demo.py — never at the live instance, whose data is real.
The script refuses to run against a URL it was not told to use and checks the
edition the stand reports before it writes anything, so a CE run cannot
silently produce EE frames.

Needs playwright with chromium:

    python3 -m venv .venv && .venv/bin/pip install playwright
    .venv/bin/python -m playwright install chromium

Frames are 1440x900 viewport captures, matching the set they replace. The
frontend has no router: App.jsx reads the tab from window.location.hash and
the selected project from localStorage['rt_project'], so a capture is a
navigation to /#<tab> with that key primed. Two frames are not tabs — the
login screen, taken before signing in, and the search overlay.
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

VIEWPORT = {"width": 1440, "height": 900}

# (file stem, tab id, needs a project selected[, edition it exists in])
#
# The numbering is the one README.md already references; keeping it means the
# documentation keeps working without touching every embed. Tabs that exist in
# the router but were never documented (overview, access, watch, purple,
# connections, user-settings) are deliberately not captured.
TABS = [
    ("02_projects", "projects", False),
    ("03_network", "network", True),
    ("04_hosts", "hosts", True),
    ("05_creds", "creds", True),
    ("06_findings", "findings", True),
    ("07_notes", "notes", True),
    ("08_loot", "loot", True),
    ("09_kb", "kb", True),
    ("11_jobs", "jobs", True),
    ("12_objectives", "objectives", True),
    ("13_attackpath", "attackpath", True),
    ("14_scope", "scope", True),
    ("15_attackgraph", "attackgraph", True),
    ("16_report", "report", True),
    ("17_timeline", "timeline", True),
    ("18_scans", "scans", True),
    ("19_playbooks", "playbooks", True),
    ("20_automations", "automations", True),
    ("21_cheatsheet", "cheatsheet", True),
    # Enterprise only: Community has no Infrastructure page at all, so there
    # is nothing to photograph there — see EDITIONS.md.
    ("22_platformops", "platform-ops", True, "ee"),
    ("23_workstations", "workstations", True),
    ("24_roe", "roe", True),
    ("25_checklist", "checklist", True),
    ("26_admin_admin", "admin", False),
    ("26_admin_devops", "admin", False),
    ("26_admin_audit", "audit", False),
    ("26_admin_organizations", "organizations", False),
    ("26_admin_system", "system", False),
]


def api(base: str, path: str, cookie: str = "") -> dict:
    req = urllib.request.Request(f"{base}{path}")
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def settle(page, deadline_s: float = 8.0) -> None:
    """Wait for the view to stop fetching and stop saying 'Loading'.

    networkidle alone is not enough: useEntitlement fails open while it loads,
    so an EE page photographed too early shows features as available before
    the real answer arrives. The loading-text check is the backstop.

    It is also not always reachable — the DevOps log and the workstation
    action feed poll on a timer, so those pages never go idle. Hence the
    deadline: wait for quiet, but never block on a page that is quiet by
    design only between polls.
    """
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
    # Let CSS transitions and the reveal animations finish before the shutter.
    time.sleep(0.6)


def check_rendered(page, stem: str, browser) -> None:
    """Refuse to photograph a crashed page.

    main.jsx's error boundary replaces the whole app with "Umbryx — rendering
    error" and the exception text. That is a perfectly good-looking screenshot
    of nothing, and it has shipped into a set before: a stray comma put a hole
    in the Enterprise tab registry and took the Infrastructure page down, and
    the run wrote the frame without complaint.
    """
    if page.locator("text=Umbryx — rendering error").count():
        detail = page.inner_text("body").strip().replace("\n", " ")[:200]
        browser.close()
        raise SystemExit(f"error: {stem} crashed the app: {detail}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="http://localhost:8899", help="demo stand base URL")
    ap.add_argument("--out", required=True, help="directory to write the PNGs into")
    ap.add_argument("--edition", required=True, choices=["ce", "ee"])
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="Demo2024!")
    ap.add_argument("--project", default="", help="project id (default: the first active one)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Refuse the live instance outright. Its database holds real hosts,
    # credentials and findings, and the whole point of the stand is that those
    # never reach a published PNG.
    if ":8888" in base:
        return fail("port 8888 is the live instance — capture the demo stand instead")

    try:
        status = api(base, "/api/auth/status")
    except (urllib.error.URLError, TimeoutError) as exc:
        return fail(f"{base} is not answering: {exc}")
    if not status.get("initialized"):
        return fail("the stand has no users yet — run scripts/demo-stand.sh up first")

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport=VIEWPORT, device_scale_factor=1)
        page = ctx.new_page()

        # 01_login — before signing in, so it has to come first.
        page.goto(f"{base}/", wait_until="networkidle")
        settle(page)
        page.screenshot(path=str(out / "01_login.png"))
        print("  01_login")

        # One login for the whole run: /api/auth/login is rate limited to
        # 5/minute per IP and ten failures lock the account.
        page.fill('input[placeholder="username"]', args.user)
        page.fill('input[type=password]', args.password)
        page.click('button:has-text("Sign in")')
        try:
            page.wait_for_selector('input[placeholder="username"]', state="detached", timeout=20000)
        except PWTimeout:
            browser.close()
            return fail("login did not go through — check the credentials")
        settle(page)

        cookie = "; ".join(f"{c['name']}={c['value']}" for c in ctx.cookies())
        edition = api(base, "/api/system/edition", cookie)
        if edition.get("edition") != args.edition:
            browser.close()
            return fail(
                f"the stand reports edition {edition.get('edition')!r}, "
                f"but this run was told {args.edition!r} — capturing it would "
                "put the wrong screens in the wrong set"
            )
        print(f"  edition={edition['edition']} tier={edition.get('tier')}")

        pid = args.project
        if not pid:
            projects = api(base, "/api/projects", cookie)
            items = projects if isinstance(projects, list) else projects.get("items", [])
            active = [p for p in items if p.get("status") == "active"]
            if not active:
                browser.close()
                return fail("the stand has no active project — is it seeded?")
            pid = active[0]["id"]
        page.evaluate("pid => localStorage.setItem('rt_project', pid)", pid)
        print(f"  project={pid}")

        for entry in TABS:
            stem, tab, _needs_project = entry[:3]
            only_in = entry[3] if len(entry) > 3 else None
            if only_in and only_in != args.edition:
                print(f"  {stem} — skipped, not in this edition")
                continue
            page.goto(f"{base}/#{tab}", wait_until="domcontentloaded")
            settle(page)
            if stem == "26_admin_devops":
                # Admin opens on User Management; the log is another section.
                # The frame before this one is also #admin, and a goto to a URL
                # that differs only in the hash is a same-document navigation —
                # nothing re-renders and the section buttons are whatever the
                # previous frame left behind. Reload to get a clean mount, then
                # wait for the buttons: the view is lazy-loaded and its
                # Suspense fallback carries no "Loading" text for settle().
                page.reload(wait_until="domcontentloaded")
                settle(page)
                try:
                    page.wait_for_selector('button:has-text("DevOps Log")', timeout=20000)
                except PWTimeout:
                    browser.close()
                    return fail("Admin never rendered its section buttons")
                page.click('button:has-text("DevOps Log")')
                settle(page)
            if stem == "04_hosts":
                # The documented frame is the tabbed detail panel
                # (Details / Activity / Creds / Path), which needs a host
                # selected. The list is built from divs, not a table; each row
                # carries id="host-<id>" (HostsView.jsx uses it to scroll a
                # focused host into view).
                row = page.locator('[id^="host-"]').first
                if not row.count():
                    browser.close()
                    return fail("no host rows on #hosts — is the stand seeded?")
                row.click()
                settle(page)
            check_rendered(page, stem, browser)
            page.screenshot(path=str(out / f"{stem}.png"))
            print(f"  {stem}")

        # 10_search — the Ctrl+K overlay, not a tab. Taken over the Knowledge
        # Base, as the frame it replaces was.
        page.goto(f"{base}/#kb", wait_until="domcontentloaded")
        settle(page)
        page.keyboard.press("Control+k")
        page.wait_for_timeout(500)
        page.keyboard.type("admin", delay=40)
        settle(page)
        page.screenshot(path=str(out / "10_search.png"))
        print("  10_search")

        browser.close()

    written = sorted(p.name for p in out.glob("*.png"))
    odd = [
        p.name
        for p in out.glob("*.png")
        if _dimensions(p) != (VIEWPORT["width"], VIEWPORT["height"])
    ]
    if odd:
        return fail(f"not 1440x900: {', '.join(odd)}")
    print(f"\n{len(written)} frames in {out}, all {VIEWPORT['width']}x{VIEWPORT['height']}")
    return 0


def _dimensions(path: Path) -> tuple[int, int]:
    """Width and height straight out of the PNG IHDR chunk."""
    with path.open("rb") as fh:
        head = fh.read(24)
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
