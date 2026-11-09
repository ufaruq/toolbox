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
