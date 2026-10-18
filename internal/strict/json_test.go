package strict

import "testing"

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
