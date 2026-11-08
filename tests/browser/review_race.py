#!/usr/bin/env python3
"""Hold real fixture review responses while the owner changes the selection."""

import os
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from fixture_e2e import FIXTURE_NOTICE, FixtureBrowser, fixture_origin


def check_selection_change(page, origin, artifact_dir, field, change_back):
    flow = FixtureBrowser(page, origin, artifact_dir)
    page.goto(origin + "/", wait_until="domcontentloaded")
    expect(page.locator("#fixture-notice")).to_be_visible()
    expect(page.locator("#fixture-notice")).to_have_text(FIXTURE_NOTICE)
    flow.click_response("login", "/fixture/login")
    expect(page.locator("#workspace")).to_be_visible()
    assert page.evaluate(
        "async () => (await (await fetch('/v1/session')).json()).fixture"
    ) is True, "Refusing mutations outside explicit fixture mode"

    # Persisted accounts can outlive the in-memory synthetic provider. Create
    # and select two fresh connections for this scenario on every run.
    previous = {item["id"] for item in page.evaluate(
        "async () => (await fetch('/v1/connections')).json()")}
    # Use two actual active connections, rather than injecting select options.
    for _ in range(2):
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.locator("#connect").click()
        expect(page.locator("#workspace")).to_be_visible()
    current = page.evaluate("async () => (await fetch('/v1/connections')).json()")
    connections = sorted(item["id"] for item in current
                         if item["status"] == "active" and item["id"] not in previous)
    assert len(connections) == 2, "Expected two newly connected fixture accounts"
    page.locator("#connection").select_option(connections[0])
    flow.click_response("create-agent", "/v1/agents", 201)
    page.locator("#file-id").fill("doc-A")
    requested, _ = flow.click_response("request", "/v1/delegation-requests", 201)
    original_id = requested["request_id"]
    other, _ = flow.click_response("request", "/v1/delegation-requests", 201)
    page.locator("#request-id").fill(original_id)

    # Start from an existing review: a new review must clear it synchronously.
    flow.review(original_id)
    held = []

    def hold_review(route):
        response = route.fetch()
        assert response.status == 200, "Fixture review was not successful"
        held.append((route, response))
        page.locator("#review").evaluate(
            "button => button.dataset.responseHeld = 'true'"
        )

    review_url = origin + f"/v1/delegation-requests/{original_id}/review"
    page.route(review_url, hold_review)
    page.locator("#review").click()
    expect(page.locator("#review")).to_have_attribute("data-response-held", "true")
    expect(page.locator("#review-details")).to_be_hidden()
    expect(page.locator("#approve")).to_be_disabled()

    if field == "request-id":
        page.locator("#request-id").fill(other["request_id"])
        if change_back:
            page.locator("#request-id").fill(original_id)
    else:
        page.locator("#connection").select_option(connections[1])
        if change_back:
            page.locator("#connection").select_option(connections[0])

    route, response = held.pop()
    route.fulfill(response=response)
    # The button is restored in the async action's finally block, after the
    # response has been processed. This avoids arbitrary timing sleeps.
    expect(page.locator("#review")).to_be_enabled()
    expect(page.locator("#review-details")).to_be_hidden()
    expect(page.locator("#approve")).to_be_disabled()

    approvals = []
    page.on("request", lambda request: approvals.append(request.url)
            if request.method == "POST"
            and urlsplit(request.url).path.endswith("/approve") else None)
    # Even an explicitly dispatched click must find no old reviewed object.
    page.locator("#approve").dispatch_event("click")
    expect(page.locator("#status")).to_have_text("Review the request first.")
    expect(page.locator("#approve")).to_be_disabled()
    assert not approvals, "A stale approval was submitted"
    expect(page.locator("#grant-id")).to_have_value("")
    assert not flow.javascript_errors, "Unhandled browser JavaScript exception"
    assert not flow.external_requests, "Browser requested outside the fixture origin"

    # A fresh review of the current selection must still work normally.
    page.unroute(review_url, hold_review)
    flow.review(page.locator("#request-id").input_value())


def main():
    try:
        origin = fixture_origin()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    artifact_dir = Path(tempfile.mkdtemp(prefix="toolbox-review-race-"))
    failures = []
    with sync_playwright() as playwright:
        launch = {"headless": True, "args": ["--disable-dev-shm-usage"]}
        if executable := os.environ.get("TOOLBOX_BROWSER_EXECUTABLE"):
            launch["executable_path"] = executable
        browser = playwright.chromium.launch(**launch)
        try:
            for field in ("request-id", "connection"):
                for change_back in (False, True):
                    name = field + (" away-and-back" if change_back else " changed")
                    context = browser.new_context()
                    page = context.new_page()
                    page.set_default_timeout(15000)
                    try:
                        check_selection_change(page, origin, artifact_dir, field, change_back)
                        print(f"PASS delayed review: {name}")
                    except Exception as error:
                        failures.append(name)
                        # Playwright call logs may contain credentials. Keep
                        # diagnostics limited to the scenario and error class.
                        print(f"FAIL delayed review: {name} ({type(error).__name__})",
                              file=sys.stderr)
                    finally:
                        context.close()
        finally:
            browser.close()
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
