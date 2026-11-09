// Package githubapp manages server-side short-lived installation credentials.
// Token scope is not a substitute for Toolbox resource authorization: GitHub
// can permit reads of public repositories outside an installation's selection.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ufaruq/toolbox/internal/strict"
)

var ErrConfiguration = errors.New("GITHUB_APP_INVALID_CONFIGURATION")
var ErrUnavailable = errors.New("GITHUB_APP_UNAVAILABLE")
var ErrScope = errors.New("GITHUB_APP_INVALID_TOKEN_SCOPE")

// Credential is secret material. Never persist it in domain.State or log it.
type Credential struct {
	Token     string `json:"-"`
	ExpiresAt time.Time
}
type Issuer struct {
	appID   string
	key     *rsa.PrivateKey
	baseURL string
	http    *http.Client
	now     func() time.Time
}

func New(appID string, keyPEM []byte) (*Issuer, error) {
	if appID == "" || strings.TrimSpace(appID) != appID || len(appID) > 128 {
		return nil, ErrConfiguration
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrConfiguration
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		key, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		v, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e == nil {
			key, _ = v.(*rsa.PrivateKey)
		}
	}
	if key == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, ErrConfiguration
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxResponseHeaderBytes = 16 << 10
	return &Issuer{appID: appID, key: key, baseURL: "https://api.github.com", http: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: time.Now}, nil
}

func permissions(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, ErrConfiguration
	}
	out := map[string]string{"metadata": "read"}
	for k, v := range in {
		switch k {
		case "contents", "issues", "pull_requests":
			if v != "read" && v != "write" {
				return nil, ErrConfiguration
			}
		case "metadata", "actions", "checks":
			if v != "read" {
				return nil, ErrConfiguration
			}
		default:
			return nil, ErrConfiguration
		}
		out[k] = v
	}
	return out, nil
}

func (i *Issuer) jwt() (string, error) {
	now := i.now()
	payload, _ := json.Marshal(map[string]any{"iss": i.appID, "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	enc := base64.RawURLEncoding.EncodeToString
	unsigned := enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc(payload)
	sum := sha256.Sum256([]byte(unsigned))
	sig, e := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if e != nil {
		return "", ErrUnavailable
	}
	return unsigned + "." + enc(sig), nil
}
func validToken(t string) bool {
	if len(t) < 16 || len(t) > 4096 {
		return false
	}
	for _, r := range t {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-._~+/=", r)) {
			return false
		}
	}
	return true
}

// Issue accepts only an installation/repository pair previously verified and
// authorized by the owner-connection layer. It never discovers caller authority.
func (i *Issuer) Issue(ctx context.Context, installationID, repositoryID int64, requested map[string]string) (Credential, error) {
	p, e := permissions(requested)
	if e != nil || installationID <= 0 || repositoryID <= 0 {
		return Credential{}, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	jwt, e := i.jwt()
	if e != nil {
		return Credential{}, e
	}
	body, _ := json.Marshal(map[string]any{"repository_ids": []int64{repositoryID}, "permissions": p})
	req, e := http.NewRequestWithContext(ctx, "POST", i.baseURL+"/app/installations/"+strconv.FormatInt(installationID, 10)+"/access_tokens", bytes.NewReader(body))
	if e != nil {
		return Credential{}, ErrConfiguration
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "toolbox-github-app")
	response, e := i.http.Do(req)
	if e != nil {
		return Credential{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return Credential{}, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return Credential{}, ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if strict.Decode(raw, &fields) != nil {
		return Credential{}, ErrScope
	}
	var token string
	if json.Unmarshal(fields["token"], &token) != nil || !validToken(token) {
		return Credential{}, ErrScope
	}
	accepted := false
	defer func() {
		if !accepted {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			_ = i.Revoke(cleanup, token)
		}
	}()
	var got map[string]string
	var selection string
	var expiry time.Time
	var repos []map[string]json.RawMessage
	if strict.Decode(fields["permissions"], &got) != nil || json.Unmarshal(fields["repository_selection"], &selection) != nil || json.Unmarshal(fields["expires_at"], &expiry) != nil || strict.Decode(fields["repositories"], &repos) != nil {
		return Credential{}, ErrScope
	}
	if selection != "selected" || len(repos) != 1 || len(got) != len(p) {
		return Credential{}, ErrScope
	}
	var id int64
	if json.Unmarshal(repos[0]["id"], &id) != nil || id != repositoryID {
		return Credential{}, ErrScope
	}
	for k, v := range p {
		if got[k] != v {
			return Credential{}, ErrScope
		}
	}
	now := i.now()
	if !expiry.After(now.Add(time.Minute)) || expiry.After(now.Add(time.Hour+time.Minute)) {
		return Credential{}, ErrScope
	}
	if ctx.Err() != nil {
		return Credential{}, ErrUnavailable
	}
	accepted = true
	return Credential{Token: token, ExpiresAt: expiry}, nil
}

func (i *Issuer) Revoke(ctx context.Context, token string) error {
	if !validToken(token) {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "DELETE", i.baseURL+"/installation/token", nil)
	if e != nil {
		return ErrConfiguration
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "toolbox-github-app")
	r, e := i.http.Do(req)
	if e != nil {
		return ErrUnavailable
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		return ErrUnavailable
	}
	return nil
}

// String deliberately omits secret values when credentials are formatted.
func (c Credential) String() string {
	return fmt.Sprintf("GitHub installation credential (expires %s)", c.ExpiresAt.UTC().Format(time.RFC3339))
}
