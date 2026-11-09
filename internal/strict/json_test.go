package strict

import (
	"encoding/json"
	"testing"
)

func TestStrictJSON(t *testing.T) {
	type nested struct {
		FileID string `json:"file_id"`
	}
	type input struct {
		Tool      string `json:"tool"`
		Arguments nested `json:"arguments"`
	}
	for _, s := range []string{`{"tool":"a","tool":"b"}`, `{"Tool":"a"}`, `{"arguments":{"file_id":"a","method":"PATCH"}}`, `{"tool":"a"} {}`, `{"tool":null}`, `{"arguments":{"file_id":"a","file_id":"b"}}`} {
		var x input
		if Decode([]byte(s), &x) == nil {
			t.Errorf("accepted %s", s)
		}
	}
	var x input
	if Decode([]byte(`{"tool":"a","arguments":{"file_id":"A"}}`), &x) != nil {
		t.Fatal("valid JSON rejected")
	}
}

func TestRawMessageRetainsStrictEnvelope(t *testing.T) {
	var out struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := Decode([]byte(`{"arguments":{"branch":"main","path":"src/a"}}`), &out); err != nil {
		t.Fatal(err)
	}
	if err := Decode([]byte(`{"arguments":{"branch":"main","branch":"other"}}`), &out); err == nil {
		t.Fatal("raw duplicate key accepted")
	}
	if err := Decode([]byte(`{"Arguments":{"branch":"main"}}`), &out); err == nil {
		t.Fatal("envelope alias accepted")
	}
}
