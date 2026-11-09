package github

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultProjection(t *testing.T) {
	raw := json.RawMessage(`{"content":[{"type":"text","text":"{\"number\":7,\"title\":\"Fix\",\"token\":\"secret\",\"head\":{\"ref\":\"agent/task\",\"sha\":\"abc\",\"secret\":\"hidden\"}}"}]}`)
	b, e := ProjectResult("prs.read", raw)
	if e != nil || strings.Contains(string(b), "secret") || strings.Contains(string(b), "hidden") || !strings.Contains(string(b), "agent/task") {
		t.Fatalf("%s %v", b, e)
	}
}
func TestResultRejectsErrorsResourcesAndBounds(t *testing.T) {
	for _, raw := range []string{`{"isError":true,"content":[]}`, `{"content":[{"type":"resource_link","uri":"https://secret"}]}`, `{"content":[{"type":"resource","resource":{"blob":"eA=="}}]}`, strings.Repeat(" ", 262145)} {
		if _, e := ProjectResult("files.read", json.RawMessage(raw)); e == nil {
			t.Fatal("unsafe result accepted")
		}
	}
}
func TestFileProjection(t *testing.T) {
	raw := json.RawMessage(`{"content":[{"type":"text","text":"successfully downloaded text file (SHA: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"},{"type":"resource","resource":{"uri":"repo://private","text":"file text","mimeType":"text/plain"}}],"_meta":{"token":"secret"}}`)
	out, e := ProjectResult("files.read", raw)
	if e != nil || strings.Contains(string(out), "private") || strings.Contains(string(out), "secret") || !strings.Contains(string(out), "file text") {
		t.Fatalf("%s %v", out, e)
	}
}

func TestPinnedPullRequestCreateNormalizesNumber(t *testing.T) {
	raw := json.RawMessage(`{"content":[{"type":"text","text":"{\"id\":\"123456789\",\"url\":\"https://github.com/owner/repo/pull/36\"}"}]}`)
	out, e := ProjectResultForRepository("prs.create", raw, "owner", "repo")
	if e != nil || !strings.Contains(string(out), `"number":36`) || strings.Contains(string(out), "https:") {
		t.Fatalf("missing safe normalized number: %s %v", out, e)
	}
	for _, u := range []string{"https://github.com/other/repo/pull/36", "https://github.com/owner/repo/issues/36", "https://evil.invalid/owner/repo/pull/36", "https://github.com/owner/repo/pull/36?token=secret", "https://user@github.com/owner/repo/pull/36", "https://github.com/owner/repo/pull/036"} {
		text, _ := json.Marshal(map[string]string{"id": "123", "url": u})
		envelope, _ := json.Marshal(map[string]any{"content": []any{map[string]string{"type": "text", "text": string(text)}}})
		if _, e := ProjectResultForRepository("prs.create", envelope, "owner", "repo"); e == nil {
			t.Fatalf("accepted malformed/mismatched PR locator %s", u)
		}
	}
}
