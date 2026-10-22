// Package mcpclient calls operator-pinned Docker MCP Gateway bindings. It is an
// outbound execution primitive, not an authentication or grant-issuance API.
package mcpclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ufaruq/toolbox/internal/strict"
)

const MaxBytes = 1 << 20
const MaxArguments = 16 << 10
const ProtocolVersion = "2025-11-25"
const MaxTimeout = 20 * time.Second

var (
	ErrConfiguration      = errors.New("MCP_INVALID_CONFIGURATION")
	ErrBinding            = errors.New("MCP_BINDING_NOT_ALLOWED")
	ErrClosed             = errors.New("MCP_CLIENT_CLOSED")
	ErrToolNotAllowed     = errors.New("MCP_TOOL_NOT_ALLOWED")
	ErrSchemaChanged      = errors.New("MCP_SCHEMA_CHANGED")
	ErrArguments          = errors.New("MCP_INVALID_ARGUMENTS")
	ErrProtocol           = errors.New("MCP_GATEWAY_IDENTITY_MISMATCH")
	ErrUnavailable        = errors.New("MCP_GATEWAY_UNAVAILABLE")
	ErrResultTooLarge     = errors.New("MCP_RESULT_TOO_LARGE")
	ErrToolFailed         = errors.New("MCP_TOOL_FAILED")
	ErrUnsupportedContent = errors.New("MCP_UNSUPPORTED_CONTENT")
)

// Binding is resolved by trusted application authorization, never by forwarding
// an agent's choice of endpoint, credential or server. Epoch is connection state.
type Binding struct {
	ID, OwnerID, ConnectionID string
	Epoch                     int64
}

type Tool struct {
	Name        string
	InputSchema json.RawMessage
}

// Gateway belongs to exactly one isolated credential context. BearerToken is a
// gateway credential, not a Google/GitHub token or the incoming agent's token.
// ServerName/ServerVersion pin the gateway handshake; the operator separately
// pins downstream image identity in the gateway catalog.
type Gateway struct {
	Binding                                          Binding
	Endpoint, BearerToken, ServerName, ServerVersion string
	Tools                                            []Tool
}

type Config struct {
	Gateways []Gateway
	Timeout  time.Duration
	RootCAs  *x509.CertPool
}

type Result struct {
	Text              string
	StructuredContent json.RawMessage
}

type registered struct {
	gateway Gateway
	schemas map[string]*jsonschema.Resolved
	digests map[string]string
}

type Client struct {
	mu        sync.RWMutex
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	bindings  map[string]registered
	timeout   time.Duration
	http      *http.Client
	transport *http.Transport
}

// New snapshots operator configuration and rejects sharing endpoints or gateway
// credentials across bindings. Provider credentials never enter this package.
func New(config Config) (*Client, error) {
	if len(config.Gateways) == 0 || len(config.Gateways) > 64 || config.Timeout < 0 || config.Timeout > MaxTimeout {
		return nil, ErrConfiguration
	}
	if config.Timeout == 0 {
		config.Timeout = MaxTimeout
	}
	c := &Client{bindings: map[string]registered{}, timeout: config.Timeout}
	endpoints, tokens := map[string]bool{}, map[string]bool{}
	for _, g := range config.Gateways {
		if !validBinding(g.Binding) || g.ServerName == "" || g.ServerVersion == "" || !validToken(g.BearerToken) || len(g.Tools) == 0 || len(g.Tools) > 64 {
			return nil, ErrConfiguration
		}
		endpoint, err := canonicalEndpoint(g.Endpoint)
		if err != nil {
			return nil, ErrConfiguration
		}
		g.Endpoint = endpoint
		if _, ok := c.bindings[g.Binding.ID]; ok || endpoints[g.Endpoint] || tokens[g.BearerToken] {
			return nil, ErrConfiguration
		}
		endpoints[g.Endpoint], tokens[g.BearerToken] = true, true
		r := registered{gateway: g, schemas: map[string]*jsonschema.Resolved{}, digests: map[string]string{}}
		r.gateway.Tools = make([]Tool, len(g.Tools))
		for i, t := range g.Tools {
			if t.Name == "" || len(t.Name) > 256 {
				return nil, ErrConfiguration
			}
			if _, exists := r.schemas[t.Name]; exists {
				return nil, ErrConfiguration
			}
			digest, err := SchemaDigest(t.InputSchema)
			if err != nil {
				return nil, ErrConfiguration
			}
			object, err := decodeObject(t.InputSchema)
			if err != nil || !safeNumbers(object) {
				return nil, ErrConfiguration
			}
			var schema jsonschema.Schema
			if json.Unmarshal(t.InputSchema, &schema) != nil {
				return nil, ErrConfiguration
			}
			resolved, err := schema.Resolve(nil) // No Loader: remote references cannot fetch URLs.
			if err != nil {
				return nil, ErrConfiguration
			}
			r.schemas[t.Name], r.digests[t.Name] = resolved, digest
			r.gateway.Tools[i] = Tool{Name: t.Name, InputSchema: append(json.RawMessage(nil), t.InputSchema...)}
		}
		c.bindings[g.Binding.ID] = r
	}
	c.transport = http.DefaultTransport.(*http.Transport).Clone()
	c.transport.MaxResponseHeaderBytes = 16 << 10
	if config.RootCAs != nil {
		if c.transport.TLSClientConfig == nil {
			c.transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		c.transport.TLSClientConfig.RootCAs = config.RootCAs.Clone()
	}
	c.http = &http.Client{Transport: boundedTransport{base: c.transport}, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	return c, nil
}

// Compare and use the same canonical endpoint. Syntactic URL aliases must not
// allow two bindings to share a gateway credential context. Operators must also
// keep different DNS names/proxies from routing bindings to the same context.
func canonicalEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "/mcp" || u.RawPath != "" || u.Hostname() == "" || strings.HasSuffix(u.Host, ":") {
		return "", ErrConfiguration
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	ip := net.ParseIP(host)
	if u.Scheme != "https" && (u.Scheme != "http" || ip == nil || !ip.IsLoopback()) {
		return "", ErrConfiguration
	}
	if ip != nil {
		host = ip.String()
	} else {
		// Non-ASCII hostnames and scoped IP literals require additional alias
		// handling. Keep this private-gateway configuration in ASCII DNS form.
		if host == "" || strings.ContainsAny(host, ":%") {
			return "", ErrConfiguration
		}
		for _, r := range host {
			if r > 127 {
				return "", ErrConfiguration
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", ErrConfiguration
		}
		port = strconv.Itoa(n)
	}
	if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
		port = ""
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	return u.String(), nil
}

func validBinding(b Binding) bool {
	return b.ID != "" && b.OwnerID != "" && b.ConnectionID != "" && b.Epoch > 0
}

// Use the opaque bearer-token alphabet, whose characters survive JSON encoding
// unchanged. This also makes the credential echo guard below unambiguous.
func validToken(token string) bool {
	if len(token) < 16 || len(token) > 4096 {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/=", r)) {
			return false
		}
	}
	return true
}

func decodeObject(data []byte) (map[string]any, error) {
	var object map[string]any
	if strict.Decode(data, &object) != nil || object == nil {
		return nil, ErrArguments
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if d.Decode(&object) != nil {
		return nil, ErrArguments
	}
	return object, nil
}

// The SDK/validator decode schema numbers as float64. Fail closed outside the
// interoperable integer range; dispatch the original JSON so no value changes.
func safeNumbers(v any) bool {
	switch x := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) || math.Abs(f) > 9007199254740991 {
			return false
		}
		a, ae, ok := normalizeNumber(string(x))
		if !ok {
			return false
		}
		b, be, ok := normalizeNumber(strconv.FormatFloat(f, 'g', -1, 64))
		return ok && a == b && ae == be
	case map[string]any:
		for _, value := range x {
			if !safeNumbers(value) {
				return false
			}
		}
	case []any:
		for _, value := range x {
			if !safeNumbers(value) {
				return false
			}
		}
	}
	return true
}

// Compare decimal values without allocating an exponent-sized big integer.
// This catches constraints the SDK's float64 decoding would silently round.
func normalizeNumber(s string) (string, int64, bool) {
	var exponent int64
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		var err error
		exponent, err = strconv.ParseInt(s[i+1:], 10, 32)
		if err != nil {
			return "", 0, false
		}
		s = s[:i]
	}
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent -= int64(len(s) - i - 1)
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0", 0, true
	}
	trimmed := strings.TrimRight(s, "0")
	exponent += int64(len(s) - len(trimmed))
	if negative {
		trimmed = "-" + trimmed
	}
	return trimmed, exponent, true
}

// SchemaDigest fingerprints the full JSON schema, including constraints. Map
// ordering and whitespace do not change the digest; duplicate keys are rejected.
func SchemaDigest(schema json.RawMessage) (string, error) {
	if len(schema) == 0 || len(schema) > MaxBytes {
		return "", ErrConfiguration
	}
	object, err := decodeObject(schema)
	if err != nil {
		return "", ErrConfiguration
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return "", ErrConfiguration
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func (c *Client) lookup(b Binding) (registered, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return registered{}, ErrClosed
	}
	r, ok := c.bindings[b.ID]
	if !ok || b != r.gateway.Binding {
		return registered{}, ErrBinding
	}
	return r, nil
}

func (c *Client) operation(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	stop := context.AfterFunc(c.ctx, cancel)
	if c.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (c *Client) failure(ctx context.Context, err error) error {
	if c.ctx.Err() != nil {
		return ErrClosed
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrResultTooLarge) {
		return ErrResultTooLarge
	}
	return ErrUnavailable // Never expose server bodies, arguments or credential-bearing errors.
}

func (c *Client) connect(ctx context.Context, r registered) (*mcp.ClientSession, error) {
	httpClient := *c.http
	httpClient.Transport = authorizedTransport{base: c.http.Transport, token: r.gateway.BearerToken, endpoint: r.gateway.Endpoint, operation: ctx}
	client := mcp.NewClient(&mcp.Implementation{Name: "toolbox-outbound", Version: "1"}, &mcp.ClientOptions{
		Capabilities:   &mcp.ClientCapabilities{},
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: r.gateway.Endpoint, HTTPClient: &httpClient, MaxRetries: -1, DisableStandaloneSSE: true, MaxEventSize: MaxBytes}, &mcp.ClientSessionOptions{ProtocolVersion: ProtocolVersion})
	if err != nil {
		return nil, c.failure(ctx, err)
	}
	info := session.InitializeResult()
	if info == nil || info.ServerInfo == nil || info.ProtocolVersion != ProtocolVersion || info.ServerInfo.Name != r.gateway.ServerName || info.ServerInfo.Version != r.gateway.ServerVersion {
		_ = session.Close()
		return nil, ErrProtocol
	}
	return session, nil
}

func (c *Client) inventory(ctx context.Context, s *mcp.ClientSession, r registered) error {
	seen := map[string]bool{}
	cursor := ""
	cursors := map[string]bool{}
	for page := 0; page < 16; page++ {
		result, err := s.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			return c.failure(ctx, err)
		}
		for _, tool := range result.Tools {
			if tool == nil || seen[tool.Name] {
				return ErrSchemaChanged
			}
			seen[tool.Name] = true
			if len(seen) > 256 {
				return ErrSchemaChanged
			}
			if expected, ok := r.digests[tool.Name]; ok {
				b, err := json.Marshal(tool.InputSchema)
				if err != nil {
					return ErrSchemaChanged
				}
				digest, err := SchemaDigest(b)
				if err != nil || digest != expected {
					return ErrSchemaChanged
				}
			}
		}
		if result.NextCursor == "" {
			for name := range r.digests {
				if !seen[name] {
					return ErrSchemaChanged
				}
			}
			return nil
		}
		if cursors[result.NextCursor] {
			return ErrSchemaChanged
		}
		cursors[result.NextCursor] = true
		cursor = result.NextCursor
	}
	return ErrSchemaChanged
}

func (c *Client) ListTools(ctx context.Context, b Binding) ([]Tool, error) {
	r, err := c.lookup(b)
	if err != nil {
		return nil, err
	}
	ctx, cancel := c.operation(ctx)
	defer cancel()
	s, err := c.connect(ctx, r)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err = c.inventory(ctx, s, r); err != nil {
		return nil, err
	}
	tools := make([]Tool, len(r.gateway.Tools))
	for i, t := range r.gateway.Tools {
		tools[i] = Tool{Name: t.Name, InputSchema: append(json.RawMessage(nil), t.InputSchema...)}
	}
	_ = s.Close()
	if ctx.Err() != nil || c.ctx.Err() != nil {
		return nil, c.failure(ctx, ctx.Err())
	}
	return tools, nil
}

func (c *Client) CallTool(ctx context.Context, b Binding, name string, args json.RawMessage) (Result, error) {
	r, err := c.lookup(b)
	if err != nil {
		return Result{}, err
	}
	schema, ok := r.schemas[name]
	if !ok {
		return Result{}, ErrToolNotAllowed
	}
	if len(args) > MaxArguments {
		return Result{}, ErrArguments
	}
	object, err := decodeObject(args)
	if err != nil || !safeNumbers(object) {
		return Result{}, ErrArguments
	}
	var arguments map[string]any
	if json.Unmarshal(args, &arguments) != nil || schema.Validate(arguments) != nil {
		return Result{}, ErrArguments
	}
	args = append(json.RawMessage(nil), args...)
	ctx, cancel := c.operation(ctx)
	defer cancel()
	s, err := c.connect(ctx, r)
	if err != nil {
		return Result{}, err
	}
	defer s.Close()
	if err = c.inventory(ctx, s, r); err != nil {
		return Result{}, err
	}
	result, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return Result{}, c.failure(ctx, err)
	}
	if ctx.Err() != nil || c.ctx.Err() != nil {
		return Result{}, c.failure(ctx, ctx.Err())
	}
	if result == nil || result.IsError {
		return Result{}, ErrToolFailed
	}
	if result.NeedsInput() || len(result.InputRequests) > 0 || result.RequestState != "" {
		return Result{}, ErrUnsupportedContent
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return Result{}, ErrUnsupportedContent
	}
	if len(encoded) > MaxBytes {
		return Result{}, ErrResultTooLarge
	}
	for _, binding := range c.bindings {
		if strings.Contains(string(encoded), binding.gateway.BearerToken) {
			return Result{}, ErrUnsupportedContent
		}
	}
	var text strings.Builder
	for i, content := range result.Content {
		t, ok := content.(*mcp.TextContent)
		if !ok {
			return Result{}, ErrUnsupportedContent
		}
		if i > 0 {
			text.WriteByte('\n')
		}
		text.WriteString(t.Text)
	}
	out := Result{Text: text.String()}
	if result.StructuredContent != nil {
		out.StructuredContent, err = json.Marshal(result.StructuredContent)
		if err != nil {
			return Result{}, ErrUnsupportedContent
		}
	}
	_ = s.Close()
	if ctx.Err() != nil || c.ctx.Err() != nil {
		return Result{}, c.failure(ctx, ctx.Err())
	}
	return out, nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.cancel()
		c.transport.CloseIdleConnections()
	}
	return nil
}
