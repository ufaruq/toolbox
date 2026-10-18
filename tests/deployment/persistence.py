"""Keep synthetic authority only in process memory across an external restart."""
import http.cookiejar
import json
import time
import urllib.request
from pathlib import Path

origin = "http://127.0.0.1:18080"
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""
def call(path, body=None, credential=None, delegation=None):
    headers = {"Origin": origin}
    if body is not None:
        headers.update({"Content-Type": "application/json", "X-CSRF-Token": csrf})
    if credential:
        headers["Authorization"] = "Bearer " + credential
    if delegation:
        headers["Toolbox-Delegation"] = delegation
    request = urllib.request.Request(origin + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
    with client.open(request, timeout=10) as response:
        return json.load(response)

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
Path("/evidence/restart-ready").touch()
for _ in range(120):
    if Path("/evidence/restart-done").exists():
        break
    time.sleep(1)
else:
    raise RuntimeError("restart handshake timed out")
assert call("/v1/session")["csrf_token"] == csrf
result = call("/v1/tool-invocations", {"tool": "google_drive.read_document.v1", "grant_id": grant, "arguments": {"file_id": "doc-A"}}, credential, delegation)
assert "Synthetic document doc-A." in json.dumps(result)
Path("/evidence/restart-passed").touch()
print("PASS: persisted session, agent credential, signing key and encrypted provider generation after restart")
