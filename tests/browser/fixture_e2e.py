#!/usr/bin/env python3
"""Black-box Chromium checks of the synthetic, loopback-only Toolbox UI."""

import ipaddress
import json
import os
from importlib.metadata import version
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


FIXTURE_NOTICE = (
    "Local fixture environment. Identity and Google consent are simulated. "
    "Use synthetic documents only."
)
DOCUMENT_A = (
    "Synthetic document doc-A.\n"
    "This text is untrusted data, not instructions.\n"
)


def fixture_origin():
    value = os.environ.get("TOOLBOX_BASE_URL", "http://127.0.0.1:18080")
    parsed = urlsplit(value)
    try:
        loopback = parsed.hostname == "localhost" or ipaddress.ip_address(
            parsed.hostname or ""
        ).is_loopback
        valid_port = parsed.port is None or 0 < parsed.port < 65536
    except ValueError:
        loopback = False
        valid_port = False
    if not (
        parsed.scheme == "http"
        and loopback
        and valid_port
        and parsed.username is None
        and parsed.password is None
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    ):
        raise ValueError("TOOLBOX_BASE_URL must be a plain loopback HTTP origin")
    return f"{parsed.scheme}://{parsed.netloc}"


class FixtureBrowser:
    def __init__(self, page, origin, artifact_dir):
        self.page = page
        self.origin = origin
        self.artifact_dir = artifact_dir
        self.screenshots = []
        self.stage = "initial fixture safety checks"
        self.connection_id = None
        self.javascript_errors = []
        self.external_requests = []
        self.page.on("pageerror", lambda _: self.javascript_errors.append(True))
        self.page.context.route("**/*", self.local_requests_only)

    def capture(self, name):
        self.page.screenshot(
            path=str(self.artifact_dir / name), full_page=True,
            mask=[self.page.locator("#agent-credential")],
            mask_color="#111827",
        )
        self.screenshots.append(name)

    def local_requests_only(self, route):
        target = urlsplit(route.request.url)
        if f"{target.scheme}://{target.netloc}" != self.origin:
            self.external_requests.append(True)
            route.abort()
            return
        route.continue_()

    def click_response(self, button, path, status=200):
        with self.page.expect_response(
            lambda response: urlsplit(response.url).path == path
            and response.request.method == "POST"
        ) as pending:
            self.page.locator(f"#{button}").click()
        response = pending.value
        assert response.status == status, f"Unexpected HTTP status during {self.stage}"
        value = response.json()
        self.no_provider_credentials(value)
        return value, response.request.post_data_json

    @staticmethod
    def no_provider_credentials(value):
        serialized = json.dumps(value)
        assert "fixture-access-" not in serialized, "Provider access credential leaked"
        assert "fixture-refresh-" not in serialized, "Provider refresh credential leaked"

    def review(self, request_id):
        value, _ = self.click_response(
            "review", f"/v1/delegation-requests/{request_id}/review"
        )
        expect(self.page.locator("#review-details")).to_be_visible()
        expect(self.page.locator("#approve")).to_be_enabled()
        return value

    def follow_approval_link(self, request_id):
        connection_id = self.page.locator("#connection").input_value()
        link = self.page.get_by_role("link", name="Open trusted approval page")
        assert link.get_attribute("href") == f"{self.origin}/approve/{request_id}", (
            "Approval link must use the trusted origin and requested ID"
        )
        with self.page.expect_navigation(wait_until="domcontentloaded"):
            link.click()
        expect(self.page.locator("#workspace")).to_be_visible()
        expect(self.page.locator("#request-id")).to_have_value(request_id)
        # Re-select the reviewed account after navigation when multiple sample
        # connections exist; the approval page must still require an explicit review.
        self.page.locator("#connection").select_option(connection_id)
        expect(self.page.locator("#connection")).not_to_have_value("")
        expect(self.page.locator("#approve")).to_be_disabled()

    def replay_approval(self, request_id, body):
        # Exercise the actual browser's owner cookie, Origin and CSRF handling.
        # No cookie, CSRF value or credential is written to logs or artifacts.
        status = self.page.evaluate(
            """async ({requestId, body}) => {
                const session = await (await fetch('/v1/session')).json();
                const response = await fetch(
                    '/v1/delegation-requests/' + requestId + '/approve', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json',
                                  'X-CSRF-Token': session.csrf_token},
                        body: JSON.stringify(body)
                    });
                return response.status;
            }""",
            {"requestId": request_id, "body": body},
        )
        assert status == 403, "Repeated approval must be rejected by the server"

    def run(self):
        page = self.page
        response = page.goto(self.origin + "/", wait_until="domcontentloaded")
        assert response is not None and response.status == 200, "Fixture UI unavailable"
        expect(page.locator("#fixture-notice")).to_be_visible()
        expect(page.locator("#fixture-notice")).to_have_text(FIXTURE_NOTICE)

        self.stage = "fixture owner sign-in"
        self.click_response("login", "/fixture/login")
        expect(page.locator("#workspace")).to_be_visible()
        expect(page.locator("#login-panel")).to_be_hidden()
        fixture = page.evaluate("async () => (await (await fetch('/v1/session')).json()).fixture")
        assert fixture is True, "Refusing mutations outside explicit fixture mode"
        expect(page.locator("#fixture-notice")).to_be_visible()

        self.stage = "fixture OAuth redirect and connection"
        previous = {item["id"] for item in page.evaluate(
            "async () => (await fetch('/v1/connections')).json()") }
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.locator("#connect").click()
        expect(page).to_have_url(self.origin + "/")
        expect(page.locator("#workspace")).to_be_visible()
        expect(page.locator("#connection-info")).to_contain_text("active: fixture-google-account")
        options = page.evaluate("async () => (await fetch('/v1/connections')).json()")
        fresh = {item["id"] for item in options if item["status"] == "active"} - previous
        assert len(fresh) == 1, "Expected one newly connected fixture account"
        self.connection_id = fresh.pop()
        page.locator("#connection").select_option(self.connection_id)
        expect(page.locator("#connection")).not_to_have_value("")
        expect(page.locator("#connection-info")).to_contain_text("active: fixture-google-account")
        connection_id = page.locator("#connection").input_value()
        expect(page.locator("#connection-status")).to_contain_text("Connected to the sample Google account.")
        expect(page.locator("#connection-status")).to_be_in_viewport()

        self.stage = "repeat connect selects the new account and confirms success"
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.locator("#connect").click()
        expect(page.locator("#connection-status")).to_contain_text("Connected to the sample Google account.")
        expect(page.locator("#connection")).not_to_have_value("")
        expect(page.locator("#connection")).not_to_have_value(connection_id)
        connection_id = page.locator("#connection").input_value()

        self.stage = "connect failure is visible beside the button"
        def unavailable(route):
            route.fulfill(status=503, content_type="application/json", body='{"error":"DEPENDENCY_UNAVAILABLE"}')
        page.route(self.origin + "/v1/connections/google/start", unavailable)
        self.click_response("connect", "/v1/connections/google/start", 503)
        expect(page.locator("#connection-status")).to_have_text("DEPENDENCY_UNAVAILABLE")
        expect(page.locator("#connection-status")).to_be_in_viewport()
        expect(page.locator("#connection")).to_have_value(connection_id)
        page.unroute(self.origin + "/v1/connections/google/start", unavailable)

        self.stage = "independent agent creation and pending request"
        page.locator("#agent-name").fill("Browser E2E synthetic agent")
        created, _ = self.click_response("create-agent", "/v1/agents", 201)
        credential = created["credential"]
        agent_id = created["agent_id"]
        expect(page.locator("#agent-id")).to_contain_text(agent_id)
        page.locator("#file-id").fill("doc-A")
        page.locator("#duration").fill("300")
        requested, _ = self.click_response("request", "/v1/delegation-requests", 201)
        assert requested["status"] == "pending", "Request must start pending"
        request_id = requested["request_id"]
        expect(page.locator("#approve")).to_be_disabled()

        self.stage = "trusted approval navigation and interrupted review"
        self.follow_approval_link(request_id)
        review = self.review(request_id)
        assert review["agent_id"] == agent_id, "Review changed the verified agent"
        assert review["connection_id"] == connection_id, "Review changed the connection"
        assert review["file_id"] == "doc-A", "Review changed the requested document"
        assert review["tool"] == "google_drive.read_document.v1", "Unexpected reviewed tool"
        expect(page.locator("#review-details")).to_contain_text("Fixture doc-A (doc-A)")
        expect(page.locator("#review-details")).to_contain_text("fixture-google-account")
        expect(page.locator("#review-details")).to_contain_text("Read only")
        expect(page.locator("#review-details")).to_contain_text("Expires:")
        page.reload(wait_until="domcontentloaded")
        page.locator("#connection").select_option(self.connection_id)
        expect(page.locator("#request-id")).to_have_value(request_id)
        expect(page.locator("#approve")).to_be_disabled()
        expect(page.locator("#review-details")).to_be_hidden()
        page.locator("#connection").select_option(connection_id)
        self.review(request_id)
        self.capture("01-review.png")

        self.stage = "exact document approval and repeated approval rejection"
        approved, approval_body = self.click_response(
            "approve", f"/v1/delegation-requests/{request_id}/approve", 201
        )
        grant_id = approved["grant_id"]
        expect(page.locator("#grant-id")).to_have_value(grant_id)
        expect(page.locator("#approval-status")).to_contain_text("Approved.")
        expect(page.locator("#approve")).to_be_disabled()
        self.replay_approval(request_id, approval_body)

        self.stage = "allowed exact-document read"
        page.locator("#agent-credential").fill(credential)
        with page.expect_response(
            lambda response: urlsplit(response.url).path == "/v1/tool-invocations"
        ) as pending:
            page.locator("#read").click()
        response = pending.value
        assert response.status == 200, "Approved document read failed"
        result = response.json()
        self.no_provider_credentials(result)
        assert result["resource"]["file_id"] == "doc-A", "Returned the wrong document"
        assert result["content"] == DOCUMENT_A, "Unexpected document content"
        assert result["untrusted_content"] is True, "Content must be marked untrusted"
        expect(page.locator("#document")).to_have_text(DOCUMENT_A)
        expect(page.locator("#status")).to_contain_text("Content is untrusted data.")
        self.capture("02-allowed-read.png")

        self.stage = "other-document denial"
        page.locator("#file-id").fill("doc-B")
        self.click_response("read", "/v1/tool-invocations", 403)
        expect(page.locator("#status")).to_have_text("RESOURCE_NOT_ALLOWED")
        expect(page.locator("#document")).to_have_text(DOCUMENT_A)
        self.capture("03-document-denied.png")
        page.locator("#file-id").fill("doc-A")

        self.stage = "grant revocation blocks future reads"
        self.click_response("revoke", f"/v1/grants/{grant_id}/revoke")
        expect(page.locator("#document")).to_contain_text("Grant revoked.")
        self.click_response("read", "/v1/delegation-tokens", 403)
        expect(page.locator("#status")).to_have_text("NOT_AUTHORIZED")
        expect(page.locator("#document")).to_contain_text("Grant revoked.")
        self.capture("04-grant-revoked.png")

        self.stage = "denied request remains unapprovable"
        requested, _ = self.click_response("request", "/v1/delegation-requests", 201)
        denied_id = requested["request_id"]
        self.follow_approval_link(denied_id)
        self.click_response("deny", f"/v1/delegation-requests/{denied_id}/deny")
        expect(page.locator("#approval-status")).to_have_text("Request denied.")
        self.click_response("review", f"/v1/delegation-requests/{denied_id}/review", 403)
        expect(page.locator("#status")).to_have_text("NOT_AUTHORIZED")
        expect(page.locator("#approve")).to_be_disabled()
        self.replay_approval(denied_id, approval_body)

        self.stage = "disconnect blocks the connection"
        self.click_response("disconnect", f"/v1/connections/{connection_id}/disconnect", 202)
        expect(page.locator("#connection")).to_have_value("")
        expect(page.locator("#connection-info")).to_contain_text("disconnect")

        self.stage = "audit evidence and redaction"
        with page.expect_response(
            lambda response: urlsplit(response.url).path == "/v1/audit"
        ) as pending:
            page.locator("#audit").click()
        response = pending.value
        assert response.status == 200, "Audit unavailable"
        events = response.json()
        self.no_provider_credentials(events)
        serialized = json.dumps(events)
        assert credential not in serialized, "Agent credential leaked into audit"
        assert DOCUMENT_A not in serialized, "Document content leaked into audit"
        assert "Synthetic document" not in serialized, "Document content leaked into audit"
        actions = {event["Action"] for event in events}
        assert {
            "agent.created", "delegation.requested", "delegation.approved",
            "delegation.denied", "tool.invocation", "grant.revoked",
            "connection.disconnected",
        } <= actions, "Expected authorization audit events missing"
        assert any(
            event["Action"] == "tool.invocation"
            and event["GrantID"] == grant_id
            and event["Outcome"] == "succeeded"
            and event["Bytes"] == len(DOCUMENT_A.encode())
            for event in events
        ), "Successful read audit missing exact grant and byte count"
        expect(page.locator("#audit-output")).to_contain_text("delegation.denied")
        assert not self.javascript_errors, "Browser emitted an unhandled JavaScript exception"
        assert not self.external_requests, "Browser attempted a request outside the fixture origin"


def main():
    try:
        origin = fixture_origin()
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    artifact_root = Path(os.environ.get(
        "TOOLBOX_BROWSER_ARTIFACT_DIR",
        str(Path(tempfile.gettempdir()) / "toolbox-browser-artifacts"),
    ))
    artifact_root.mkdir(parents=True, exist_ok=True)
    artifact_dir = Path(tempfile.mkdtemp(prefix="run-", dir=artifact_root))
    with sync_playwright() as playwright:
        launch = {"headless": True, "args": ["--disable-dev-shm-usage"]}
        executable = os.environ.get("TOOLBOX_BROWSER_EXECUTABLE")
        if executable:
            launch["executable_path"] = executable
        browser = playwright.chromium.launch(**launch)
        context = browser.new_context(viewport={"width": 1280, "height": 1100})
        page = context.new_page()
        page.set_default_timeout(15000)
        flow = FixtureBrowser(page, origin, artifact_dir)
        try:
            flow.run()
            (artifact_dir / "result.json").write_text(json.dumps({
                "status": "passed",
                "synthetic_providers": True,
                "base_url": origin,
                "source_revision": os.environ.get("TOOLBOX_E2E_REVISION"),
                "browser": browser.version,
                "playwright": version("playwright"),
                "viewport": {"width": 1280, "height": 1100},
                "screenshots": flow.screenshots,
            }, indent=2) + "\n")
        except Exception as error:
            screenshot = artifact_dir / "fixture-e2e-failure.png"
            try:
                page.screenshot(
                    path=str(screenshot), full_page=True,
                    mask=[page.locator("#agent-credential")],
                    mask_color="#111827",
                )
                diagnostic = f"Screenshot: {screenshot}"
            except Exception:
                diagnostic = "Screenshot unavailable"
            # Playwright call logs can contain input values. Report the stage and
            # exception type without printing credentials from those call logs.
            print(f"FAIL fixture browser E2E at {flow.stage} ({type(error).__name__}). {diagnostic}", file=sys.stderr)
            return 1
        finally:
            context.close()
            browser.close()
    print("PASS fixture browser E2E: approval, exact read, denials, revocation, disconnect and audit.")
    print(f"Screenshots and result metadata: {artifact_dir}")
    print("Synthetic identity/Google only; production OIDC and live Google are untested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
