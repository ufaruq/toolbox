package tokens

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OpenBaoConfig describes a production KV-v2 mount. Address must be HTTPS with
// no path, userinfo, query or fragment. Token must be a least-privilege workload
// token, never a development root token. It must not be logged by the caller.
type OpenBaoConfig struct{ Address, Mount, Token, Namespace string }
type OpenBao struct {
	address, mount, token, namespace string
	client                           *http.Client
}

func NewOpenBao(c OpenBaoConfig) (*OpenBao, error) {
	return newOpenBao(c, false)
}

// NewOpenBaoFixture permits plaintext HTTP only for an explicitly selected
// local/dev fixture: loopback, localhost, or the Compose service name openbao.
// Production configuration must never select this constructor.
func NewOpenBaoFixture(c OpenBaoConfig) (*OpenBao, error) {
	return newOpenBao(c, true)
}

func newOpenBao(c OpenBaoConfig, fixture bool) (*OpenBao, error) {
	u, e := url.Parse(c.Address)
	if e != nil {
		return nil, ErrUnavailable
	}
	localHTTP := false
	if fixture && u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		localHTTP = host == "localhost" || host == "openbao" || ip != nil && ip.IsLoopback()
	}
	if (u.Scheme != "https" && !localHTTP) || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || !validPath(c.Mount) || c.Token == "" || strings.ContainsAny(c.Token+c.Namespace, "\r\n") {
		return nil, ErrUnavailable
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 20, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second}
	return &OpenBao{address: strings.TrimRight(c.Address, "/"), mount: c.Mount, token: c.Token, namespace: c.Namespace, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Ping is an authenticated read probe in the credential namespace. A missing
// probe is healthy; deployment validation must separately ensure the configured
// KV-v2 mount exists, since a missing mount can also return HTTP 404.
func (s *OpenBao) Ping(ctx context.Context) error {
	var value json.RawMessage
	_, err := s.GetJSON(ctx, Path("readiness-probe"), &value)
	if err == ErrNotFound {
		return nil
	}
	return err
}
func (s *OpenBao) Get(ctx context.Context, path string) (Bundle, int64, error) {
	var b Bundle
	v, e := s.GetJSON(ctx, path, &b)
	return b, v, e
}
func (s *OpenBao) Put(ctx context.Context, path string, b Bundle, cas int64) (int64, error) {
	return s.PutJSON(ctx, path, b, cas)
}
func (s *OpenBao) GetJSON(ctx context.Context, path string, out any) (int64, error) {
	data, e := s.do(ctx, http.MethodGet, path, nil)
	if e != nil {
		return 0, e
	}
	var envelope struct {
		Data struct {
			Data     json.RawMessage `json:"data"`
			Metadata struct {
				Version      int64  `json:"version"`
				DeletionTime string `json:"deletion_time"`
				Destroyed    bool   `json:"destroyed"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Data.Metadata.Version < 1 {
		return 0, ErrUnavailable
	}
	if envelope.Data.Metadata.Destroyed || envelope.Data.Metadata.DeletionTime != "" {
		return 0, ErrNotFound
	}
	if json.Unmarshal(envelope.Data.Data, out) != nil {
		return 0, ErrUnavailable
	}
	return envelope.Data.Metadata.Version, nil
}
func (s *OpenBao) PutJSON(ctx context.Context, path string, in any, cas int64) (int64, error) {
	if cas < 0 {
		return 0, ErrUnavailable
	}
	data, e := json.Marshal(struct {
		Data    any              `json:"data"`
		Options map[string]int64 `json:"options"`
	}{in, map[string]int64{"cas": cas}})
	if e != nil {
		return 0, ErrUnavailable
	}
	response, e := s.do(ctx, http.MethodPost, path, data)
	if e != nil {
		return 0, e
	}
	var envelope struct {
		Data struct {
			Version int64 `json:"version"`
		} `json:"data"`
	}
	if json.Unmarshal(response, &envelope) != nil || envelope.Data.Version <= cas {
		return 0, ErrUnavailable
	}
	return envelope.Data.Version, nil
}
func (s *OpenBao) DeleteJSON(ctx context.Context, path string) error {
	_, e := s.do(ctx, http.MethodDelete, path, nil)
	return e
}
func (s *OpenBao) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if !validPath(path) {
		return nil, ErrUnavailable
	}
	req, e := http.NewRequestWithContext(ctx, method, s.address+"/v1/"+s.mount+"/data/"+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("X-Vault-Token", s.token)
	if s.namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := s.client.Do(req)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(data) > 1<<20 {
		return nil, ErrUnavailable
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode == 400 && bytes.Contains(data, []byte("check-and-set")) {
		return nil, ErrCAS
	}
	if resp.StatusCode == 409 {
		return nil, ErrCAS
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrUnavailable
	}
	return data, nil
}
