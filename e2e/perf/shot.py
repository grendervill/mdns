#!/usr/bin/env python3
"""Capture a screenshot of the mdns panel while the perf harness runs.

Used by scripts/perf-local.sh. The script logs in through the real form
(the panel requires a CSRF token, so a raw POST would be rejected) and
waits for the live feed heading before taking the picture.

Environment:
  PERF_PANEL_URL       base URL, e.g. https://127.0.0.1:8443
  PERF_PANEL_PASSWORD  panel password
  PERF_SHOT            output PNG path

The Playwright venv lives in .venv-pw (gitignored, created by
scripts/e2e-panel.sh or by hand).
"""

import os
import sys

from playwright.sync_api import sync_playwright


def main() -> int:
    base = os.environ.get("PERF_PANEL_URL", "").rstrip("/")
    password = os.environ.get("PERF_PANEL_PASSWORD", "")
    shot = os.environ.get("PERF_SHOT", "")
    if not base or not password or not shot:
        print("shot.py: set PERF_PANEL_URL, PERF_PANEL_PASSWORD and PERF_SHOT", file=sys.stderr)
        return 2

    os.makedirs(os.path.dirname(shot) or ".", exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1440, "height": 1000},
        )
        page = context.new_page()
        page.goto(base + "/login", wait_until="load", timeout=15000)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_url("**/panel/", timeout=15000)
        page.wait_for_selector("text=Живая лента", timeout=15000)
        # Let the SSE feed paint a row or two before the capture.
        page.wait_for_timeout(1000)
        page.screenshot(path=shot, full_page=True)
        browser.close()

    print("shot.py: saved " + shot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
