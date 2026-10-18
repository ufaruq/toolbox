package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}
}
func metadataJSON() string {
	return `{"id":"doc_A-1","name":"Fixture document","mimeType":"application/vnd.google-apps.document","trashed":false,"modifiedTime":"2026-10-18T00:00:00Z","capabilities":{"canDownload":true}}`
}
func goodAccess(context.Context) (string, error) { return "CANARY-ACCESS", nil }
func authorize(context.Context) error            { return nil }
func plan(t *testing.T) RequestPlan {
	t.Helper()
	p, e := NewDriveReadPlan("doc_A-1")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestAllowedReadExactRequestPlan(t *testing.T) {
	calls, checks, tokens := 0, 0, 0
	exec := NewFixtureExecutor(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.URL.Scheme != "https" || r.URL.Host != "www.googleapis.com" || r.Body != nil || r.Header.Get("Authorization") != "Bearer CANARY-ACCESS" {
			t.Fatal("invalid outbound envelope")
		}
		if calls == 1 {
			if r.URL.Path != "/drive/v3/files/doc_A-1" || r.URL.Query().Get("fields") != MetadataFields || len(r.URL.Query()) != 1 {
				t.Fatal("metadata projection widened")
			}
			return response(200, metadataJSON()), nil
		}
		if r.URL.Path != "/drive/v3/files/doc_A-1/export" || r.URL.Query().Get("mimeType") != "text/plain" || len(r.URL.Query()) != 1 {
			t.Fatal("export shape widened")
		}
		return response(200, "CANARY-DOCUMENT-TEXT"), nil
	}))
	result, e := exec.Execute(context.Background(), plan(t), func(context.Context) (string, error) { tokens++; return "CANARY-ACCESS", nil }, func(context.Context) error { checks++; return nil })
	if e != nil || result.Text != "CANARY-DOCUMENT-TEXT" || result.FileID != "doc_A-1" || !result.Untrusted || result.MIMEType != "text/plain" || result.RetrievedAt.IsZero() || result.ModifiedTime.IsZero() || calls != 2 || tokens != 2 || checks < 6 {
		t.Fatal("read contract failed", e)
	}
	serialized, _ := json.Marshal(result)
	if strings.Contains(string(serialized), "CANARY-ACCESS") {
		t.Fatal("credential in connector output")
	}
}
func TestMalformedIDsBeforeAnySecretOrDispatch(t *testing.T) {
	for _, id := range []string{"", "../secret", "a/b", "a?alt=media", "a#x", "a%2fb", "a%252fb", "a.b", "a\\b", "a\x00", "ä", strings.Repeat("a", 257)} {
		if _, e := NewDriveReadPlan(id); e != ErrInvalidInput {
			t.Errorf("accepted %q", id)
		}
	}
	if !ValidFileID(strings.Repeat("a", 256)) {
		t.Fatal("valid boundary rejected")
	}
}
func TestFixedPlanRejectsHTTPBypasses(t *testing.T) {
	p := plan(t)
	tests := map[string]func(*http.Request){"write": func(r *http.Request) { r.Method = "PATCH" }, "method-override-header": func(r *http.Request) { r.Header.Set("X-HTTP-Method-Override", "PATCH") }, "other-file": func(r *http.Request) { r.URL.Path = "/drive/v3/files/other" }, "arbitrary-host": func(r *http.Request) { r.URL.Host = "localhost" }, "insecure": func(r *http.Request) { r.URL.Scheme = "http" }, "raw-path": func(r *http.Request) { r.URL.RawPath = "/drive/v3/files/doc_A%2D1" }, "query-option": func(r *http.Request) { r.URL.RawQuery += "&alt=media" }, "duplicate-query": func(r *http.Request) { r.URL.RawQuery += "&fields=id" }, "fragment": func(r *http.Request) { r.URL.Fragment = "escape" }, "userinfo": func(r *http.Request) { r.URL.User = url.User("attacker") }, "body": func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)) }, "method-override-host": func(r *http.Request) { r.Host = "other" }, "chunked-body": func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", p.endpoint(false), nil)
			mutate(r)
			if p.validate(r, false) != ErrInvalidInput {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}
func TestMetadataRestrictionsNeverExport(t *testing.T) {
	for name, body := range map[string]string{"wrong-file": strings.Replace(metadataJSON(), "doc_A-1", "other", 1), "shortcut": strings.Replace(metadataJSON(), documentMIME, "application/vnd.google-apps.shortcut", 1), "pdf": strings.Replace(metadataJSON(), documentMIME, "application/pdf", 1), "trashed": strings.Replace(metadataJSON(), `"trashed":false`, `"trashed":true`, 1), "download-restricted": strings.Replace(metadataJSON(), `"canDownload":true`, `"canDownload":false`, 1), "missing-capability": strings.Replace(metadataJSON(), `"canDownload":true`, "", 1), "invalid-json": "not json", "missing-trash": strings.Replace(metadataJSON(), `"trashed":false,`, "", 1)} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, body), nil }))
			result, e := exec.Execute(context.Background(), plan(t), goodAccess, authorize)
			if e == nil || result.Text != "" || calls != 1 {
				t.Fatal("restricted resource exported")
			}
		})
	}
}
func TestRedirectsNeverFollowed(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/private", "https://attacker.example/steal", "https://www.googleapis.com/other"} {
		calls := 0
		exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			r := response(302, "CANARY-SECRET-IN-ERROR")
			r.Header.Set("Location", target)
			return r, nil
		}))
		_, e := exec.Execute(context.Background(), plan(t), goodAccess, authorize)
		if e != ErrProvider || calls != 1 || strings.Contains(e.Error(), "CANARY") {
			t.Fatal("redirect or provider error leaked")
		}
	}
}
func TestOversizedMetadataAndExportRejected(t *testing.T) {
	for _, export := range []bool{false, true} {
		calls := 0
		exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if export && calls == 1 {
				return response(200, metadataJSON()), nil
			}
			limit := metadataLimit
			if export {
				limit = domain.MaxBytes
			}
			return response(200, strings.Repeat("x", limit+1)), nil
		}))
		result, e := exec.Execute(context.Background(), plan(t), goodAccess, authorize)
		if e != ErrTooLarge || result.Text != "" {
			t.Fatal("oversized response accepted or truncated")
		}
	}
}
func TestRevokedBeforeDispatchAndAfterResponse(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		calls, gets := 0, 0
		exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not call") }))
		_, e := exec.Execute(context.Background(), plan(t), func(context.Context) (string, error) { gets++; return "token", nil }, func(context.Context) error { return domain.ErrDenied })
		if e != domain.ErrDenied || calls != 0 || gets != 0 {
			t.Fatal("revocation crossed dispatch boundary")
		}
	})
	for _, at := range []int{1, 2} {
		calls := 0
		revoked := false
		exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			if calls == at {
				revoked = true
			}
			if calls == 1 {
				return response(200, metadataJSON()), nil
			}
			return response(200, "sensitive document"), nil
		}))
		auth := func(context.Context) error {
			if revoked {
				return domain.ErrDenied
			}
			return nil
		}
		result, e := exec.Execute(context.Background(), plan(t), goodAccess, auth)
		if e != domain.ErrDenied || result.Text != "" || calls != at {
			t.Fatal("buffered revoked content returned")
		}
	}
}
func TestRetryReauthorizesAndReacquires(t *testing.T) {
	calls, gets, checks := 0, 0, 0
	exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		if calls < 3 {
			return response(503, "temporary"), nil
		}
		if calls == 3 {
			return response(200, metadataJSON()), nil
		}
		return response(200, "text"), nil
	}))
	result, e := exec.Execute(context.Background(), plan(t), func(context.Context) (string, error) { gets++; return "token", nil }, func(context.Context) error { checks++; return nil })
	if e != nil || result.Text != "text" || calls != 4 || gets != 4 || checks < 10 {
		t.Fatal("retry did not reauthorize each dispatch")
	}
}
func Test401RefreshOnlyOncePerInvocation(t *testing.T) {
	calls, refreshes := 0, 0
	exec := NewFixtureExecutor(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			return response(200, metadataJSON()), nil
		}
		return response(401, "unauthorized"), nil
	}))
	_, e := exec.Execute(context.Background(), plan(t), func(ctx context.Context) (string, error) {
		if RefreshRequested(ctx) {
			refreshes++
			return "new-token", nil
		}
		return "old-token", nil
	}, authorize)
	if e != ErrReauth || calls != 3 || refreshes != 1 {
		t.Fatal("401 refresh budget exceeded", calls, refreshes, e)
	}
}
func Test403NeverRefreshesAndRetriesBounded(t *testing.T) {
	for _, status := range []int{403, 429, 500} {
		calls, refreshes := 0, 0
		exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(status, "failure"), nil }))
		_, _ = exec.Execute(context.Background(), plan(t), func(ctx context.Context) (string, error) {
			if RefreshRequested(ctx) {
				refreshes++
			}
			return "token", nil
		}, authorize)
		want := 3
		if status == 403 {
			want = 1
		}
		if calls != want || refreshes != 0 {
			t.Fatal("retry policy violated", status, calls)
		}
	}
}
func TestCancellationAndPublicAddressFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exec := NewFixtureExecutor(roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("cancelled dispatch"); return nil, nil }))
	if _, e := exec.Execute(ctx, plan(t), goodAccess, authorize); e == nil {
		t.Fatal("cancelled execution succeeded")
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.0.1", "100.64.0.1", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "198.18.1.1"} {
		if publicIP(netip.MustParseAddr(address)) {
			t.Fatal("private/reserved target allowed", address)
		}
	}
	if !publicIP(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address denied")
	}
}
func TestProductionTransportHasNoAmbientProxy(t *testing.T) {
	e := NewExecutor()
	transport, ok := e.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.MinVersion < 0x0303 || e.client.Timeout != 20*time.Second {
		t.Fatal("unsafe production transport")
	}
	if e.client.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect policy changed")
	}
}
