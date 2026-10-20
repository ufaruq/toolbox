"""Verify persistent authority using a protected, temporary synthetic checkpoint."""
import http.cookiejar
import json
import sys
import os
import urllib.request
from pathlib import Path

origin = "http://127.0.0.1:18080"
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""
cookie = ""
def call(path, body=None, credential=None, delegation=None):
    headers = {"Origin": origin}
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers.update({"Content-Type": "application/json", "X-CSRF-Token": csrf})
    if credential:
        headers["Authorization"] = "Bearer " + credential
    if delegation:
        headers["Toolbox-Delegation"] = delegation
    request = urllib.request.Request(origin + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    with client.open(request, timeout=10) as response:
        return json.load(response)

state_path = Path("/state/restart.json")
if sys.argv[1] == "before":
    csrf = call("/fixture/login", {})["csrf_token"]
    a = call("/v1/agents", {"name": "Restart verification"})
    credential = a["credential"]
    # The existing fixture browser flow establishes a connection; isolate this owner
    # session's fresh connection rather than selecting old persisted data.
    previous = {c["id"] for c in call("/v1/connections")}
    start = call("/v1/connections/google/start", {})
    with client.open(start["authorization_url"], timeout=10) as response:
        response.read()
    connections = call("/v1/connections")
    fresh = [c for c in connections if c["status"] == "active" and c["id"] not in previous]
    assert len(fresh) == 1
    connection = fresh[0]["id"]
    r = call("/v1/delegation-requests", {"tool": "google_drive.read_document.v1", "file_id": "doc-A", "duration_seconds": 3600}, credential)
    review = call("/v1/delegation-requests/" + r["request_id"] + "/review", {"connection_id": connection})
    grant = call("/v1/delegation-requests/" + r["request_id"] + "/approve", {"connection_id": connection, "version": review["version"], "digest": review["digest"]})["grant_id"]
    delegation = call("/v1/delegation-tokens", {"grant_id": grant}, credential)["delegation_token"]
    state = {"csrf": csrf, "cookie": "; ".join(c.name + "=" + c.value for c in jar),
             "credential": credential, "grant": grant, "delegation": delegation}
    fd = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream)
    print("Prepared protected synthetic restart checkpoint")
elif sys.argv[1] == "after":
    assert state_path.stat().st_mode & 0o077 == 0
    state = json.loads(state_path.read_text())
    csrf, cookie = state["csrf"], state["cookie"]
    try:
        assert call("/v1/session")["csrf_token"] == csrf
        result = call("/v1/tool-invocations", {"tool": "google_drive.read_document.v1", "grant_id": state["grant"], "arguments": {"file_id": "doc-A"}}, state["credential"], state["delegation"])
        assert "Synthetic document doc-A." in json.dumps(result)
    finally:
        state_path.unlink()
    print("PASS: persisted session, agent credential, signing key and encrypted provider generation after restart")
else:
    raise SystemExit("unknown checkpoint phase")
