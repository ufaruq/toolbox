package connectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/domain"
)

const driveHost = "www.googleapis.com"
const MetadataFields = "id,name,mimeType,trashed,modifiedTime,capabilities(canDownload)"
const documentMIME = "application/vnd.google-apps.document"
const metadataLimit = 64 << 10

type refreshKey struct{}
type executionState struct{ refreshed bool }

// RefreshRequested is a trusted executor hint for the token callback. It is set
// only after a provider 401, never from invocation JSON or HTTP headers.
func RefreshRequested(ctx context.Context) bool { v, _ := ctx.Value(refreshKey{}).(bool); return v }

type RequestPlan struct{ fileID string }

func NewDriveReadPlan(fileID string) (RequestPlan, error) {
	if !ValidFileID(fileID) {
		return RequestPlan{}, ErrInvalidInput
	}
	return RequestPlan{fileID: fileID}, nil
}
func ValidFileID(id string) bool {
	if len(id) < 1 || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func (p RequestPlan) endpoint(export bool) string {
	path := "https://" + driveHost + "/drive/v3/files/" + p.fileID
	if export {
		return path + "/export?" + url.Values{"mimeType": []string{"text/plain"}}.Encode()
	}
	return path + "?" + url.Values{"fields": []string{MetadataFields}}.Encode()
}
func (p RequestPlan) validate(req *http.Request, export bool) error {
	if !ValidFileID(p.fileID) || req == nil || req.URL == nil || req.Method != http.MethodGet || req.URL.String() != p.endpoint(export) || req.URL.User != nil || req.URL.RawPath != "" || req.URL.Fragment != "" || req.URL.Opaque != "" || req.ContentLength != 0 || len(req.Header) != 0 || len(req.TransferEncoding) != 0 || (req.Body != nil && req.Body != http.NoBody) || (req.Host != "" && req.Host != driveHost) {
		return ErrInvalidInput
	}
	return nil
}

// Executor owns the only credential-bearing HTTP client. No caller-supplied URL,
// transport, header, or HTTP method is accepted by the production constructor.
type Executor struct {
	client  *http.Client
	fixture bool
}

func NewExecutor() *Executor {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 8 * time.Second, MaxIdleConns: 32, MaxIdleConnsPerHost: 16, IdleConnTimeout: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil || host != driveHost || port != "443" {
			return nil, ErrProvider
		}
		addresses, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(addresses) == 0 {
			return nil, ErrProvider
		}
		for _, ip := range addresses {
			if !publicIP(ip) {
				return nil, ErrProvider
			}
		}
		for _, ip := range addresses {
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, ErrProvider
	}
	return &Executor{client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// NewFixtureExecutor is intentionally a separate, explicit test/demo boundary.
// Never wire untrusted input or a caller-selected transport to this constructor.
func NewFixtureExecutor(transport http.RoundTripper) *Executor {
	if transport == nil {
		panic("fixture transport required")
	}
	return &Executor{fixture: true, client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(prefix).Contains(ip) {
			return false
		}
	}
	return true
}
func (e *Executor) Inspect(ctx context.Context, p RequestPlan, access AccessFunc, authorize AuthorizeFunc) (Metadata, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return e.inspect(ctx, p, access, authorize, &executionState{})
}
func (e *Executor) inspect(ctx context.Context, p RequestPlan, access AccessFunc, authorize AuthorizeFunc, state *executionState) (Metadata, error) {
	var out Metadata
	data, err := e.dispatch(ctx, p, false, metadataLimit, access, authorize, state)
	if err != nil {
		return out, err
	}
	var metadata struct {
		ID           string    `json:"id"`
		Name         string    `json:"name"`
		MIMEType     string    `json:"mimeType"`
		Trashed      *bool     `json:"trashed"`
		ModifiedTime time.Time `json:"modifiedTime"`
		Capabilities struct {
			CanDownload *bool `json:"canDownload"`
		} `json:"capabilities"`
	}
	if json.Unmarshal(data, &metadata) != nil {
		return out, ErrProvider
	}
	if metadata.ID != p.fileID || metadata.MIMEType != documentMIME || metadata.Trashed == nil || *metadata.Trashed || metadata.ModifiedTime.IsZero() {
		return out, ErrUnsupported
	}
	if metadata.Capabilities.CanDownload == nil || !*metadata.Capabilities.CanDownload {
		return out, ErrRestricted
	}
	if err = authorize(ctx); err != nil {
		return out, err
	}
	return Metadata{ID: metadata.ID, Name: metadata.Name, MIMEType: metadata.MIMEType, ModifiedTime: metadata.ModifiedTime}, nil
}
func (e *Executor) Execute(ctx context.Context, p RequestPlan, access AccessFunc, authorize AuthorizeFunc) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out Result
	state := &executionState{}
	metadata, err := e.inspect(ctx, p, access, authorize, state)
	if err != nil {
		return out, err
	}
	data, err := e.dispatch(ctx, p, true, domain.MaxBytes, access, authorize, state)
	if err != nil {
		return out, err
	}
	if err = authorize(ctx); err != nil {
		return out, err
	}
	return Result{FileID: p.fileID, Text: string(data), MIMEType: "text/plain", ModifiedTime: metadata.ModifiedTime, RetrievedAt: time.Now().UTC(), Untrusted: true}, nil
}
func (e *Executor) dispatch(ctx context.Context, p RequestPlan, export bool, limit int, access AccessFunc, authorize AuthorizeFunc, state *executionState) ([]byte, error) {
	if access == nil || authorize == nil || !ValidFileID(p.fileID) {
		return nil, ErrInvalidInput
	}
	refreshNext := false
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil, ErrProvider
		}
		if err := authorize(ctx); err != nil {
			return nil, err
		}
		tokenCtx := ctx
		if refreshNext {
			tokenCtx = context.WithValue(ctx, refreshKey{}, true)
			refreshNext = false
		}
		token, err := access(tokenCtx)
		if err != nil {
			return nil, err
		}
		if token == "" || strings.ContainsAny(token, "\r\n") {
			return nil, ErrReauth
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint(export), nil)
		if err != nil || p.validate(req, export) != nil {
			return nil, ErrInvalidInput
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if export {
			req.Header.Set("Accept", "text/plain")
		} else {
			req.Header.Set("Accept", "application/json")
		}
		if err = authorize(ctx); err != nil {
			return nil, err
		}
		response, err := e.client.Do(req)
		if err != nil {
			return nil, ErrProvider
		}
		status := response.StatusCode
		if status == http.StatusOK {
			if response.ContentLength > int64(limit) {
				response.Body.Close()
				return nil, ErrTooLarge
			}
			data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
			response.Body.Close()
			if readErr != nil {
				return nil, ErrProvider
			}
			if len(data) > limit {
				return nil, ErrTooLarge
			}
			if err = authorize(ctx); err != nil {
				return nil, err
			}
			return data, nil
		}
		retryAfter := response.Header.Get("Retry-After")
		response.Body.Close()
		if status == http.StatusUnauthorized {
			if state.refreshed || attempt == 2 {
				return nil, ErrReauth
			}
			state.refreshed = true
			refreshNext = true
			continue
		}
		if status == http.StatusForbidden {
			return nil, ErrRestricted
		}
		if (status == http.StatusTooManyRequests || status >= 500 && status <= 599) && attempt < 2 {
			if err = waitRetry(ctx, attempt, retryAfter); err != nil {
				return nil, err
			}
			continue
		}
		return nil, ErrProvider
	}
	return nil, ErrProvider
}
func waitRetry(ctx context.Context, attempt int, value string) error {
	delay := time.Duration(50+rand.IntN(101)) * time.Millisecond * time.Duration(1<<attempt)
	if value != "" {
		var d time.Duration
		if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
			if seconds > 2 {
				return ErrProvider
			}
			d = time.Duration(seconds) * time.Second
		} else if at, err := http.ParseTime(value); err == nil {
			d = time.Until(at)
			if d > 2*time.Second {
				return ErrProvider
			}
		}
		if d > delay {
			delay = d
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ErrProvider
	}
}
