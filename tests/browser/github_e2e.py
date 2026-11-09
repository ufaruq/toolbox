"""Synthetic provider, real Toolbox HTTP server, owner UI and Chromium."""
import os
from playwright.sync_api import sync_playwright, expect

origin = os.environ["TOOLBOX_GITHUB_TEST_ORIGIN"]
stage = "startup"
try:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        context.add_cookies([{"name": "toolbox_session", "value": os.environ["TOOLBOX_GITHUB_TEST_COOKIE"], "url": origin, "httpOnly": True, "sameSite": "Lax"}])
        page = context.new_page()
        failures = []
        page.on("pageerror", lambda _: failures.append("page error"))
        page.on("dialog", lambda d: (failures.append("unexpected dialog"), d.dismiss()))
        page.goto(origin + "/github")
        stage = "repository connection"
        expect(page.get_by_role("heading", name="Your GitHub repositories")).to_be_visible()
        page.locator("#repository").select_option("100")
        page.get_by_role("button", name="Connect repository", exact=True).click()
        expect(page.locator("#connections")).to_contain_text("org/browser-repo")
        state = context.request.get(origin + "/v1/github/state").json()
        conn = next(c for c in state["connections"] if c["RepositoryID"] == 100)
        headers = {"Authorization": os.environ["TOOLBOX_GITHUB_TEST_AGENT"]}
        made = context.request.post(origin + "/v1/github/requests", headers=headers, data={"connection_id": conn["ID"], "duration_seconds": 3600, "scope": {"actions": ["files.read"], "branches": ["main"], "paths": ["src/"]}})
        assert made.status == 201
        stage = "owner review"
        page.goto(made.json()["approval_url"])
        expect(page.locator("#review")).to_be_visible()
        expect(page.locator("#review-details")).to_contain_text("src/")
        expect(page.locator("#review-details")).to_contain_text("<img src=x onerror=alert(1)>")
        assert page.locator("#review-details img").count() == 0
        page.get_by_role("button", name="Approve this scope", exact=True).click()
        expect(page.locator("#status")).to_contain_text("Scope approved")
        request = context.request.get(origin + "/v1/github/requests/" + made.json()["request_id"], headers=headers).json()
        assert request["status"] == "approved"
        stage = "invoke and revoke"
        args = {"grant_id": request["grant_id"], "action": "files.read", "arguments": {"branch": "main", "path": "src/main.go"}}
        result = context.request.post(origin + "/v1/github/invoke", headers=headers, data=args)
        assert result.status == 200 and result.json()["result"]["content"] == "bounded fixture"
        grant_row = page.locator("#grants > div").filter(has_text="Repository 100")
        grant_row.get_by_role("button", name="Revoke access", exact=True).click()
        expect(page.locator("#status")).to_have_text("Access revoked.")
        assert context.request.post(origin + "/v1/github/invoke", headers=headers, data=args).status == 403
        stage = "narrow viewport"
        page.set_viewport_size({"width": 375, "height": 812})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not failures
        browser.close()
    print("PASS: synthetic GitHub browser connect, review, approve, invoke, revoke, untrusted text and narrow layout")
except Exception:
    print("FAIL: synthetic GitHub stage=" + stage)
    raise SystemExit(1)
