package github

import (
	"encoding/json"
	"regexp"
	"unicode/utf8"
)

var resultSHA = regexp.MustCompile(`SHA: ([0-9a-f]{40})`)

// ProjectResult accepts the JSON MCP CallToolResult envelope, discards upstream
// metadata/links and projects bounded data. It never fetches resource links.
// The caller must treat returned text as untrusted data, not instructions.
func ProjectResult(action string, raw json.RawMessage) (json.RawMessage, error) {
	if _, e := Permissions(action); e != nil {
		return nil, e
	}
	if len(raw) > 256<<10 || !utf8.Valid(raw) {
		return nil, ErrDenied
	}
	var envelope struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			Resource *struct {
				Text *string `json:"text"`
				Blob string  `json:"blob"`
			} `json:"resource"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.IsError || len(envelope.Content) == 0 || len(envelope.Content) > 4 {
		return nil, ErrDenied
	}
	out := map[string]any{}
	if action == "files.read" {
		for _, c := range envelope.Content {
			switch c.Type {
			case "text":
				if match := resultSHA.FindStringSubmatch(c.Text); len(match) == 2 {
					out["sha"] = match[1]
				}
			case "resource":
				if c.Resource == nil || c.Resource.Text == nil || c.Resource.Blob != "" || !textOK(*c.Resource.Text, 64<<10, false) {
					return nil, ErrDenied
				}
				if _, exists := out["content"]; exists {
					return nil, ErrDenied
				}
				out["content"] = *c.Resource.Text
			default:
				return nil, ErrDenied
			}
		}
		if _, ok := out["content"]; !ok {
			return nil, ErrDenied
		}
		if _, ok := out["sha"]; !ok {
			return nil, ErrDenied
		}
	} else {
		if len(envelope.Content) != 1 || envelope.Content[0].Type != "text" {
			return nil, ErrDenied
		}
		text := envelope.Content[0].Text
		var payload map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &payload) != nil {
			// The reviewed review tool returns only a completion message. Do not forward
			// arbitrary provider error prose or invented success for other operations.
			if action != "prs.review" || text != "pull request review submitted successfully" {
				return nil, ErrDenied
			}
			out["completed"] = true
		} else {
			keys := []string{"number", "id", "sha", "ref", "title", "body", "state", "draft", "merged", "mergeable", "mergeable_state", "message"}
			for _, k := range keys {
				if v, ok := payload[k]; ok {
					var x any
					if json.Unmarshal(v, &x) != nil {
						return nil, ErrDenied
					}
					switch x.(type) {
					case string, bool, float64:
					default:
						continue
					}
					out[k] = x
				}
			}
			for _, k := range []string{"head", "base", "commit", "content", "object"} {
				if v, ok := payload[k]; ok {
					var nested map[string]json.RawMessage
					if json.Unmarshal(v, &nested) != nil {
						continue
					}
					safe := map[string]any{}
					for _, field := range []string{"ref", "sha", "path", "name", "type"} {
						var v string
						if json.Unmarshal(nested[field], &v) == nil {
							safe[field] = v
						}
					}
					if len(safe) > 0 {
						out[k] = safe
					}
				}
			}
			if len(out) == 0 {
				return nil, ErrDenied
			}
		}
	}
	b, e := json.Marshal(out)
	if e != nil || len(b) > 64<<10 {
		return nil, ErrDenied
	}
	return b, nil
}
