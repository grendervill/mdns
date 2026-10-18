#!/usr/bin/env python3
"""Browser end-to-end test of the mdns web panel.

The test drives a real Chromium against the panel of a real installation
inside a systemd container (scripts/e2e-panel.sh brings the container up
and installs mdns). It is deliberately written against the rendered UI —
selectors, labels, URLs and the live feed — not against the Go handlers,
so a regression in a template or in app.js fails here even when the
handler tests stay green.

What it covers (the task's non-negotiables):

  * anonymous /panel/ redirects to /login and renders the form;
  * a wrong password shows the error and stays on /login;
  * the right password lands on the Статус page with all four gauges,
    all four diagrams, the live feed and the section headings;
  * hovering a donut segment shows the tooltip with the segment label;
  * clicking the «заблокировано» segment opens the history filtered to
    outcome=blocked, and every row on that page is blocked;
  * searching a generated qname substring filters the history; 130
    matching rows give «страница 1 из 2» at 100 per page, and «вперёд →»
    opens page 2 with the remaining 30;
  * a POST without the CSRF token is rejected with 403;
  * the live feed receives a query issued from inside the container over
    SSE (the feed is cleared first, so the grow is unambiguous);
  * 390x844 renders the status page without horizontal overflow;
  * --disabled: with the panel off, /panel/ and /login answer 404 (the
    second run of the harness installs without --password).

Screenshots go to PANEL_SHOTS (e2e/panel/shots by default) and are
committed with the test.

Environment:
  PANEL_BASE_URL   panel origin, e.g. https://127.0.0.1:8443
                   (default https://127.0.0.1:8443)
  PANEL_PASSWORD   the admin password installed in the container
  PANEL_CONTAINER  docker container name, used to issue DNS traffic with
                   dig from inside the installation (not needed by
                   --disabled)
  PANEL_SHOTS      screenshot directory (default e2e/panel/shots)

Usage:
  .venv-pw/bin/python e2e/panel/panel_test.py
  .venv-pw/bin/python e2e/panel/panel_test.py --disabled
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("PANEL_BASE_URL", "https://127.0.0.1:8443").rstrip("/")
PASSWORD = os.environ.get("PANEL_PASSWORD", "")
CONTAINER = os.environ.get("PANEL_CONTAINER", "")
SHOTS = Path(os.environ.get("PANEL_SHOTS", "e2e/panel/shots"))

checks = 0
failed = 0


def check(desc, ok, detail=""):
    """Records one assertion; a failed one does not stop the run."""
    global checks, failed
    checks += 1
    if ok:
        print("  \u2713 %s" % desc, flush=True)
    else:
        failed += 1
        print("  \u2717 %s" % desc, flush=True)
        if detail:
            for line in str(detail).splitlines():
                print("      %s" % line, flush=True)
    return ok


def need(desc, ok, detail=""):
    """A precondition: failing it aborts the run, later steps cannot run."""
    if not check(desc, ok, detail):
        raise RuntimeError(desc)


def dig(name):
    """Issues one plain-DNS query from inside the installation."""
    subprocess.run(
        [
            "docker", "exec", CONTAINER,
            "dig", "@127.0.0.1", name, "A", "+short",
            "+timeout=3", "+tries=1",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def ring_point(ring):
    """Returns the viewport point at the middle of a donut segment.

    The whole point of a ring is that its center is empty: Playwright's
    own hover/click targets the center of the element's bounding box,
    which is the hole, so the test computes the midpoint of the painted
    dash instead (circumference is drawn as a percentage of the path,
    see internal/panel/status.go donut()).
    """
    return ring.evaluate(
        """(el) => {
            const svg = el.ownerSVGElement;
            const box = svg.getBoundingClientRect();
            const parts = (el.getAttribute('stroke-dasharray') || '')
                .split(/[\\s,]+/).map(Number);
            const dash = parts[0] || 0;
            const offset = Number(el.getAttribute('stroke-dashoffset') || 0);
            // The dash pattern starts at `offset` into the path; the
            // painted part is [0, dash) in pattern space, so its middle
            // maps to path position dash/2 - offset (mod 100). The circle
            // path starts at 3 o'clock and runs clockwise.
            const p = (((dash / 2 - offset) % 100) + 100) % 100;
            const a = (p / 100) * Math.PI * 2;
            const scale = box.width / 42; // the viewBox is 42x42
            return {
                x: box.left + (21 + 15.9 * Math.cos(a)) * scale,
                y: box.top + (21 + 15.9 * Math.sin(a)) * scale,
                dash: dash,
                label: el.getAttribute('data-label'),
            };
        }""",
    )


def panel_flow(page, context):
    """The full signed-in scenario; called once per run."""
    SHOTS.mkdir(parents=True, exist_ok=True)

    page_errors = []
    csp_errors = []
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))

    def on_console(msg):
        if msg.type == "error" and (
            "Content Security Policy" in msg.text or "Refused to" in msg.text
        ):
            csp_errors.append(msg.text)

    page.on("console", on_console)

    # --- anonymous access ------------------------------------------------
    resp = context.request.get(BASE_URL + "/panel/", max_redirects=0)
    need(
        "anonymous GET /panel/ redirects to /login",
        resp.status in (302, 303) and resp.headers.get("location", "").endswith("/login"),
        "status %s, location %r" % (resp.status, resp.headers.get("location")),
    )
    check(
        "anonymous GET /panel/ answers with an empty or tiny body (no page)",
        len(resp.body()) < 512,
        "body: %r" % resp.body()[:200],
    )

    page.goto(BASE_URL + "/panel/")
    need("the anonymous GET lands on the login page", page.url.endswith("/login"))
    password = page.locator("input[name=password]")
    need("the login form has a password field", password.is_visible())
    check(
        "the login page names the admin account and the server-side hash",
        "admin" in page.locator("body").inner_text()
        and "argon2id" in page.locator("body").inner_text(),
    )
    page.screenshot(path=str(SHOTS / "login.png"), full_page=True)

    # --- wrong password --------------------------------------------------
    password.fill("definitely-not-the-password")
    page.get_by_role("button", name="Войти").click()
    alert = page.locator(".alert[role=alert]")
    alert.wait_for(state="visible", timeout=5000)
    need("a wrong password renders an error message", alert.is_visible())
    check(
        "the error names the wrong password (the generic message)",
        "Неверный пароль" in alert.inner_text(),
        alert.inner_text(),
    )
    check("a wrong password stays on the login page", page.url.endswith("/login"))

    # --- correct password ------------------------------------------------
    password = page.locator("input[name=password]")
    password.fill(PASSWORD)
    page.get_by_role("button", name="Войти").click()
    page.wait_for_url(re.compile(r"/panel/$"))
    page.wait_for_load_state()

    need(
        "the correct password lands on the Статус page",
        page.locator(".topline h2").inner_text() == "Статус",
        page.locator(".topline").inner_text() if page.locator(".topline").count() else "no topline",
    )
    gauges = page.locator(".gauges .g")
    check("the status page renders four gauges", gauges.count() == 4, gauges.count())
    gauge_text = page.locator(".gauges").inner_text()
    for label in ("Запросов всего", "Кеш", "Заблокировано", "Лучший upstream"):
        check("gauge %r is present" % label, label in gauge_text)

    pies = page.locator(".piefold .pie")
    check("the status page renders four diagrams", pies.count() == 4, pies.count())
    pie_text = page.locator(".piefold").inner_text()
    for label in ("Ответы", "Протоколы", "Кто ответил", "Клиенты"):
        check("diagram %r is present" % label, label in pie_text)

    feed = page.locator("#feed")
    check("the live feed block is present", feed.count() == 1)
    check(
        "the status page has the three section headings",
        page.locator("main h3").count() >= 3,
        page.locator("main h3").all_inner_texts(),
    )
    check(
        "the rail carries all seven sections",
        page.locator(".rail .nav a").count() == 7,
        page.locator(".rail .nav a").all_inner_texts(),
    )
    # The gauge is "{{.Blocked}}<small>{{.BlockedPercent}}</small>" with no
    # separator, so read the value's text node, not the element's text.
    blocked_raw = gauges.nth(2).locator(".v").evaluate(
        "el => (el.firstChild ? el.firstChild.textContent : '').replace(/\\s/g, '')"
    )
    check(
        "the blocked gauge counts the generated blocked queries",
        blocked_raw.isdigit() and int(blocked_raw) >= 5,
        "blocked gauge: %r" % blocked_raw,
    )

    # The traffic was generated before this page opened; the feed must show
    # it, which also proves the server-side buffer was seeded.
    page.wait_for_function(
        "document.querySelectorAll('#feed .q').length > 0", timeout=15000
    )
    rows = page.locator("#feed .q")
    check("the feed shows the generated traffic", rows.count() > 0, rows.count())
    page.screenshot(path=str(SHOTS / "status-desktop.png"), full_page=True)

    # --- the other rail pages -------------------------------------------
    # The rail is the panel's own navigation; walking it proves each page
    # renders end to end (status 200, its heading, and a clean console),
    # not only that the handler exists. The collectors are already on the
    # desktop page, so a JavaScript or CSP failure on any page reds here.
    rail_pages = [
        ("/panel/upstreams", "Upstream’ы"),
        ("/panel/filters", "Фильтры"),
        ("/panel/cert", "Сертификат"),
        ("/panel/settings", "Настройки"),
        ("/panel/maintenance", "Обслуживание"),
    ]
    for href, name in rail_pages:
        with page.expect_navigation() as nav:
            page.locator('.rail .nav a[href="%s"]' % href).click()
        resp = nav.value
        check(
            "the rail opens %s with HTTP 200" % name,
            resp is not None and resp.status == 200,
            "response: %r" % (resp.status if resp is not None else None),
        )
        heading = page.locator(".topline h2").inner_text()
        check(
            "%s renders its heading" % name,
            name in heading,
            heading,
        )
        check("no JavaScript error on %s" % name, not page_errors, page_errors)
        check("no CSP violation on %s" % name, not csp_errors, csp_errors)

    # Back to the status page for the chart interaction below.
    with page.expect_navigation() as nav:
        page.locator('.rail .nav a[href="/panel/"]').click()
    page.wait_for_load_state()

    # --- donut hover and the blocked-segment click -----------------------
    blocked_ring = page.locator('.pie .ring[data-label="заблокировано"]')
    need(
        "the «заблокировано» donut segment is drawn",
        blocked_ring.count() == 1,
        "ring count: %d" % blocked_ring.count(),
    )
    point = ring_point(blocked_ring)
    check(
        "the «заблокировано» segment has a non-zero painted arc",
        point["dash"] > 0,
        point,
    )
    page.mouse.move(point["x"], point["y"])
    page.wait_for_function(
        "document.getElementById('tip').style.opacity === '1'", timeout=5000
    )
    tip_text = page.locator("#tip").inner_text()
    check(
        "hovering the segment makes the tooltip visible with its label",
        "заблокировано" in tip_text,
        tip_text,
    )
    check(
        "the tooltip carries the value and the click hint",
        "·" in tip_text and "клик" in tip_text,
        tip_text,
    )

    page.mouse.click(point["x"], point["y"])
    page.wait_for_url(re.compile(r"/panel/history\?.*outcome=blocked"))
    page.wait_for_load_state()
    check(
        "the segment click opens the history filtered to outcome=blocked",
        "outcome=blocked" in page.url,
        page.url,
    )
    hist_tags = page.locator(".wire.hist .q .tag").all_inner_texts()
    check(
        "the filtered history has blocked rows",
        len(hist_tags) >= 5,
        "rows: %d" % len(hist_tags),
    )
    check(
        "every row on the blocked page is tagged «блок»",
        hist_tags and all(t.strip() == "блок" for t in hist_tags),
        hist_tags,
    )
    page.screenshot(path=str(SHOTS / "history-filtered.png"), full_page=True)

    # --- search and pagination ------------------------------------------
    page.goto(BASE_URL + "/panel/history")
    search = page.locator("input[name=q]")
    need("the history page has the search box", search.is_visible())
    search.fill("e2e-search")
    search.press("Enter")
    page.wait_for_url(re.compile(r"[?&]q=e2e-search"))
    page.wait_for_load_state()

    names = page.locator(".wire.hist .q .name").all_inner_texts()
    check(
        "the search returns the first page of matching rows",
        len(names) == 100,
        "rows: %d" % len(names),
    )
    check(
        "every search row matches the typed substring",
        names and all("e2e-search" in n for n in names),
        names[:3],
    )
    pager = page.locator(".pager").inner_text()
    check(
        "the pager reports page 1 of 2 at 100 per page",
        "страница 1 из 2" in pager and "по 100 на страницу" in pager,
        pager,
    )
    page.get_by_role("link", name="вперёд →").click()
    page.wait_for_url(re.compile(r"[?&]page=2"))
    page.wait_for_load_state()
    names2 = page.locator(".wire.hist .q .name").all_inner_texts()
    pager2 = page.locator(".pager").inner_text()
    check(
        "«вперёд →» opens page 2 with the remaining 30 rows",
        len(names2) == 30,
        "rows: %d; pager: %s" % (len(names2), pager2),
    )
    check(
        "page 2 still carries the search filter and reports 2 of 2",
        "q=e2e-search" in page.url
        and "страница 2 из 2" in pager2
        and all("e2e-search" in n for n in names2),
        page.url,
    )
    page.screenshot(path=str(SHOTS / "history-page2.png"), full_page=True)

    # --- CSRF negative ---------------------------------------------------
    csrf = context.request.post(
        BASE_URL + "/panel/upstreams/toggle", form={"id": "cloudflare"}
    )
    check(
        "an authenticated POST without the CSRF token is 403",
        csrf.status == 403,
        "status %d: %s" % (csrf.status, csrf.text()[:120]),
    )

    # --- live feed over SSE ---------------------------------------------
    page.goto(BASE_URL + "/panel/")
    page.wait_for_function(
        "document.querySelectorAll('#feed .q').length > 0", timeout=15000
    )
    page.locator("#feed-clear").click()
    page.wait_for_function(
        "document.querySelectorAll('#feed .q').length === 0", timeout=5000
    )
    check("«Очистить» empties the visible feed", page.locator("#feed .q").count() == 0)

    live_name = "e2e-live-%d.example.com" % os.getpid()
    dig(live_name)
    # qlog stores the absolute name, so the rendered qname carries the
    # trailing root dot.
    try:
        page.wait_for_function(
            "(() => { const n = document.querySelector('#feed .q .name');"
            " return n && n.textContent.replace(/\\.$/, '') === %s; })()"
            % json.dumps(live_name),
            timeout=15000,
        )
        live_ok = True
    except Exception:  # noqa: BLE001 - reported as the assertion below
        live_ok = False
    check(
        "the SSE feed gains the query issued inside the container",
        live_ok,
        "feed: %r" % page.locator("#feed .q .name").all_inner_texts()[:3],
    )
    check(
        "the live row is the newest one",
        page.locator("#feed .q .name").first.inner_text().rstrip(".") == live_name,
        page.locator("#feed .q .name").all_inner_texts()[:3],
    )

    # --- mobile ----------------------------------------------------------
    mobile = context.new_page()
    mobile.set_viewport_size({"width": 390, "height": 844})
    mobile.goto(BASE_URL + "/panel/")
    mobile.wait_for_load_state()
    check(
        "the status page renders at 390x844",
        mobile.locator(".topline h2").is_visible()
        and mobile.locator(".gauges .g").count() == 4
        and mobile.locator(".piefold .pie").count() == 4,
    )
    # The pre-fix layout let the long latency/source cell squeeze the
    # qname to a sliver (~10px, rendered "d" for doubleclick.ne.jp). A
    # width floor plus a non-trivial text length fails that layout while
    # the fixed one keeps the name at ~190px. scrollWidth is reported for
    # the record (it catches clipping separately).
    mobile.wait_for_function(
        "document.querySelectorAll('#feed .q').length > 0", timeout=15000
    )
    blocked_names = mobile.locator("#feed .q:has(.tag.block) .name")
    need(
        "the mobile feed shows a blocked row",
        blocked_names.count() > 0,
        "feed rows: %d" % mobile.locator("#feed .q").count(),
    )
    name_metrics = blocked_names.first.evaluate(
        """el => ({
            width: el.clientWidth,
            scroll: el.scrollWidth,
            text: el.textContent,
        })"""
    )
    check(
        "the blocked qname keeps a readable width at 390px (>= 60px)",
        name_metrics["width"] >= 60,
        name_metrics,
    )
    check(
        "the blocked qname renders more than a clipped letter",
        len(name_metrics["text"].strip()) >= 4,
        name_metrics,
    )
    print(
        "      (mobile blocked qname: %dpx wide, %dpx scroll, text %r)"
        % (name_metrics["width"], name_metrics["scroll"], name_metrics["text"]),
        flush=True,
    )
    overflow = mobile.evaluate(
        "() => document.documentElement.scrollWidth - window.innerWidth"
    )
    check(
        "the mobile page has no horizontal overflow",
        overflow <= 1,
        "scrollWidth exceeds the viewport by %spx" % overflow,
    )
    mobile.screenshot(path=str(SHOTS / "mobile.png"), full_page=True)
    mobile.close()

    # --- scripting health -------------------------------------------------
    check("no uncaught JavaScript error on the panel pages", not page_errors, page_errors)
    check("no CSP violation was logged", not csp_errors, csp_errors)


def disabled_flow(context):
    """The panel-off run: the routes must not reveal themselves."""
    for path in ("/panel/", "/login", "/panel/static/app.css"):
        # No redirect following: a 404 that had to be discovered after a
        # hop would still leave the route visible on the wire.
        resp = context.request.get(BASE_URL + path, max_redirects=0)
        check(
            "%s answers 404 when the panel is off" % path,
            resp.status == 404,
            "status %d" % resp.status,
        )
        check(
            "%s carries no Location header when the panel is off" % path,
            not resp.headers.get("location"),
            "location: %r" % resp.headers.get("location"),
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--disabled",
        action="store_true",
        help="the panel-off run: assert /panel/ and /login are 404",
    )
    args = parser.parse_args()

    if not args.disabled and not PASSWORD:
        print("panel_test: PANEL_PASSWORD is not set", file=sys.stderr)
        return 2
    if not args.disabled and not CONTAINER:
        print("panel_test: PANEL_CONTAINER is not set", file=sys.stderr)
        return 2

    print("--- panel browser checks (%s) ---" % BASE_URL, flush=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            locale="ru-RU",
            viewport={"width": 1280, "height": 900},
            device_scale_factor=1,
        )
        try:
            if args.disabled:
                disabled_flow(context)
            else:
                page = context.new_page()
                panel_flow(page, context)
        finally:
            context.close()
            browser.close()

    print(
        "panel tests: %d assertions, %d failed" % (checks, failed),
        flush=True,
    )
    if failed:
        print("e2e-panel: browser checks FAILED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
