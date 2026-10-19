#!/usr/bin/env python3
"""Synthetic OIDC browser acceptance, invoked by TestOIDCBrowserFlow only."""

import base64
import ipaddress
import json
import os
from importlib.metadata import version
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright


NOTICE = (
    "Local owner sign-in only. Google connections, document access and agent "
    "features are not configured."
)


def test_origin(setting, scheme):
    parsed = urlsplit(os.environ.get(setting, ""))
    try:
        loopback = parsed.hostname == "localhost" or ipaddress.ip_address(
            parsed.hostname or ""
        ).is_loopback
        valid_port = parsed.port is not None and 0 < parsed.port < 65536
    except ValueError:
        loopback = False
        valid_port = False
    if not (
        parsed.scheme == scheme and loopback and valid_port
        and parsed.username is None and parsed.password is None
        and parsed.path == "" and not parsed.query and not parsed.fragment
    ):
        raise ValueError("The harness must supply exact synthetic loopback origins")
    return f"{parsed.scheme}://{parsed.netloc}"


def request_origin(url):
    parsed = urlsplit(url)
    if parsed.username is not None or parsed.password is not None:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


class OIDCBrowser:
    def __init__(self, browser, app_origin, idp_origin, artifact_dir):
        self.browser = browser
        self.app_origin = app_origin
        self.idp_origin = idp_origin
        self.artifact_dir = artifact_dir
        self.stage = "synthetic origin configuration"
        self.screenshots = []
        self.javascript_errors = []
        self.external_requests = []
        self.contexts = []

    def new_page(self):
        context = self.browser.new_context(
            viewport={"width": 1280, "height": 960}, service_workers="block",
            accept_downloads=False,
        )
        self.contexts.append(context)
        context.route("**/*", self.local_requests_only)
        context.route_web_socket("**/*", self.reject_web_socket)
        page = context.new_page()
        page.set_default_timeout(10000)
        page.set_default_navigation_timeout(20000)
        page.on("pageerror", lambda _: self.javascript_errors.append(True))
        return page

    def local_requests_only(self, route):
        if request_origin(route.request.url) not in (self.app_origin, self.idp_origin):
            self.external_requests.append(True)
            route.abort("blockedbyclient")
        else:
            route.continue_()

    def reject_web_socket(self, socket):
        # HTTP routing does not cover WebSockets. This flow needs no sockets;
        # close the browser side without opening an upstream connection.
        self.external_requests.append(True)
        socket.close(code=1008, reason="Sockets are disabled for synthetic owner tests")

    def capture(self, page, name):
        assert page.url == self.app_origin + "/", "Unexpected screenshot location"
        page.screenshot(path=str(self.artifact_dir / name), full_page=True)
        self.screenshots.append(name)

    def session(self, page):
        result = page.evaluate("""async () => {
            const response = await fetch('/v1/session', {cache: 'no-store'});
            return {status: response.status, body: await response.json()};
        }""")
        assert result["status"] == 200, "Owner session was unavailable"
        session = result["body"]
        assert session.get("fixture") is False, "Fixture mode was enabled"
        assert session.get("owner_only") is True, "Owner-only mode was unavailable"
        assert isinstance(session.get("user_id"), str) and session["user_id"]
        assert isinstance(session.get("csrf_token"), str) and session["csrf_token"]
        return session

    def sign_in(self, page, subject):
        self.stage = "initial owner page navigation"
        page.goto(self.app_origin + "/", wait_until="domcontentloaded")
        self.stage = "initial owner capabilities and UI"
        expect(page.locator("#owner-notice")).to_have_text(NOTICE)
        expect(page.locator("#login")).to_have_text("Sign in with Okta")
        expect(page.locator("#login")).to_be_enabled()
        expect(page.locator("#owner-panel")).to_be_hidden()
        for selector in ("#fixture-notice", "#workspace", "#connect", "#agent-credential"):
            assert page.locator(selector).count() == 0, "Fixture or tool UI was exposed"
        config = page.evaluate("""async () => {
            const response = await fetch('/v1/auth/config', {cache: 'no-store'});
            return {status: response.status, body: await response.json()};
        }""")
        assert config == {"status": 200, "body": {
            "fixture": False, "owner_only": True, "login_url": "/auth/oidc/start"
        }}, "Unexpected public owner capabilities"
        self.stage = "authorization start"
        with page.expect_response(
            lambda response: request_origin(response.url) == self.app_origin
            and urlsplit(response.url).path == "/auth/oidc/start"
        ) as started:
            page.locator("#login").click()
        response = started.value
        assert response.status == 200, "Owner login could not start"
        self.stage = "synthetic provider navigation"
        page.wait_for_url(lambda url: request_origin(str(url)) == self.idp_origin)
        # Read the browser's destination after navigation. The initiating fetch
        # body can be discarded by Chromium when its document is replaced.
        authorization = urlsplit(page.url)
        assert request_origin(authorization.geturl()) == self.idp_origin
        query = parse_qs(authorization.query)
        assert query.get("scope") == ["openid"], "Unexpected identity scopes"
        assert query.get("response_type") == ["code"]
        assert query.get("code_challenge_method") == ["S256"]
        assert query.get("redirect_uri") == [self.app_origin + "/auth/oidc/callback"]
        assert "client_secret" not in query
        expect(page.locator("#subject")).to_be_visible()
        page.locator("#subject").fill(subject)
        self.stage = "synthetic provider authorization and callback"
        with page.expect_response(
            lambda response: request_origin(response.url) == self.app_origin
            and urlsplit(response.url).path == "/auth/oidc/callback"
        ) as completed:
            page.locator("#authorize").click()
        assert completed.value.status in (302, 303), "Owner callback failed"
        self.stage = "signed-in owner page"
        page.wait_for_url(self.app_origin + "/")
        expect(page.locator("#owner-panel")).to_be_visible()
        expect(page.locator("#login-panel")).to_be_hidden()
        session = self.session(page)
        expect(page.locator("#owner-id")).to_have_text(session["user_id"])
        cookies = page.context.cookies(self.app_origin)
        session_cookie = next(cookie for cookie in cookies if cookie["name"] == "toolbox_session")
        assert session_cookie["httpOnly"] and session_cookie["sameSite"] == "Lax"
        assert session_cookie["path"] == "/"
        assert not any(cookie["name"] == "toolbox_login" for cookie in cookies)
        return session["user_id"], session_cookie["value"]

    def logout(self, page, old_cookie):
        with page.expect_response(
            lambda response: urlsplit(response.url).path == "/v1/session/logout"
        ) as logged_out:
            page.locator("#logout").click()
        assert logged_out.value.status == 200, "Toolbox logout failed"
        expect(page.locator("#owner-panel")).to_be_hidden()
        expect(page.locator("#login")).to_be_enabled()
        expect(page.locator("#owner-id")).to_have_text("")
        denied = page.context.request.get(
            self.app_origin + "/v1/session", max_redirects=0,
            headers={"Cookie": "toolbox_session=" + old_cookie},
        )
        assert denied.status in (401, 403), "Logged-out session remained usable"
        page.reload(wait_until="domcontentloaded")
        expect(page.locator("#login")).to_be_enabled()
        expect(page.locator("#owner-panel")).to_be_hidden()

    def run(self):
        self.stage = "first owner redirect and verified session"
        first = self.new_page()
        first_id, first_cookie = self.sign_in(first, "browser-owner-one")
        self.stage = "session reload and CSRF rejection"
        first.reload(wait_until="domcontentloaded")
        expect(first.locator("#owner-panel")).to_be_visible()
        assert self.session(first)["user_id"] == first_id, "Reload changed owner identity"
        denied = first.evaluate("""async () => {
            const response = await fetch('/v1/session/logout', {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'
            });
            return response.status;
        }""")
        assert denied == 403, "Logout without CSRF was accepted"
        assert self.session(first)["user_id"] == first_id
        self.stage = "live session with stale CSRF"
        first.evaluate("csrfToken = 'stale-csrf'")
        with first.expect_response(
            lambda response: urlsplit(response.url).path == "/v1/session/logout"
        ) as csrf_logout:
            first.locator("#logout").click()
        assert csrf_logout.value.status == 403
        expect(first.locator("#status")).not_to_be_empty()
        expect(first.locator("#owner-panel")).to_be_visible()
        expect(first.locator("#login-panel")).to_be_hidden()
        assert "Signed out" not in first.locator("#status").inner_text()
        first.reload(wait_until="domcontentloaded")
        expect(first.locator("#owner-panel")).to_be_visible()
        self.capture(first, "01-owner-signed-in.png")

        self.stage = "independent second owner"
        second = self.new_page()
        second_id, second_cookie = self.sign_in(second, "browser-owner-two")
        assert first_id != second_id, "Distinct subjects shared an internal owner"
        assert first_cookie != second_cookie, "Independent owners shared a browser session"
        assert self.session(first)["user_id"] == first_id
        self.capture(second, "02-second-owner.png")

        self.stage = "local logout and old-session denial"
        self.logout(first, first_cookie)
        assert self.session(second)["user_id"] == second_id, "Logout revoked another browser"
        self.capture(first, "03-owner-signed-out.png")
        stale_tab = second.context.new_page()
        stale_tab.goto(self.app_origin + "/", wait_until="domcontentloaded")
        expect(stale_tab.locator("#owner-panel")).to_be_visible()
        self.logout(second, second_cookie)
        self.stage = "logout after another tab ended the session"
        with stale_tab.expect_response(
            lambda response: urlsplit(response.url).path == "/v1/session/logout"
        ) as expired_logout:
            stale_tab.locator("#logout").click()
        assert expired_logout.value.status == 403
        expect(stale_tab.locator("#owner-panel")).to_be_hidden()
        expect(stale_tab.locator("#login")).to_be_enabled()
        assert not self.javascript_errors, "Unhandled JavaScript exception"
        assert not self.external_requests, "A request escaped the two synthetic origins"


def main():
    stage = "synthetic origin configuration"
    flow = None
    try:
        # Driver diagnostics include query strings even when our exceptions are
        # sanitized. Keep those logs disabled for direct invocations too.
        for key in tuple(os.environ):
            if key in ("DEBUG", "DEBUG_FILE", "PWDEBUG") or key.startswith(("PW_TEST_DEBUG", "PW_TEST_TRACE")):
                os.environ.pop(key, None)
        app_origin = test_origin("TOOLBOX_OIDC_TEST_APP_ORIGIN", "http")
        idp_origin = test_origin("TOOLBOX_OIDC_TEST_IDP_ORIGIN", "https")
        assert app_origin != idp_origin
        spki = os.environ.get("TOOLBOX_OIDC_TEST_IDP_SPKI", "")
        assert len(base64.b64decode(spki, validate=True)) == 32, "Invalid synthetic certificate pin"
        artifact_root = Path(os.environ.get(
            "TOOLBOX_BROWSER_ARTIFACT_DIR", Path(tempfile.gettempdir()) / "toolbox-browser-artifacts"
        ))
        artifact_root.mkdir(parents=True, exist_ok=True)
        artifact_dir = Path(tempfile.mkdtemp(prefix="oidc-run-", dir=artifact_root))
        stage = "Chromium launch"
        with sync_playwright() as playwright:
            options = {"headless": True, "args": [
                "--ignore-certificate-errors-spki-list=" + spki,
            ]}
            executable = os.environ.get("TOOLBOX_BROWSER_EXECUTABLE")
            if executable:
                options["executable_path"] = executable
            browser = playwright.chromium.launch(**options)
            try:
                flow = OIDCBrowser(browser, app_origin, idp_origin, artifact_dir)
                flow.run()
                revision = os.environ.get("TOOLBOX_E2E_REVISION", "")
                metadata = {
                    "result": "passed", "scope": "synthetic OIDC owner sign-in only",
                    "live_okta_acceptance": "unrun", "owner_count": 2,
                    "browser_version": browser.version, "playwright_version": version("playwright"),
                    "viewport": {"width": 1280, "height": 960},
                    "revision": revision if re.fullmatch(r"[0-9a-f]{40,64}", revision) else None,
                    "screenshots": flow.screenshots,
                    "javascript_errors": len(flow.javascript_errors),
                    "external_requests": len(flow.external_requests),
                }
                (artifact_dir / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
            finally:
                browser.close()
        print("Synthetic OIDC browser acceptance passed. Artifacts: " + str(artifact_dir))
        return 0
    except Exception as error:
        # Playwright exceptions may contain callback query strings or cookies.
        # Print only our fixed stage and the exception type, never its message.
        print("Synthetic OIDC browser acceptance failed at " +
              (flow.stage if flow else stage) + " (" + type(error).__name__ + ").", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
