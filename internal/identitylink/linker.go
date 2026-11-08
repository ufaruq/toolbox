// Package identitylink performs an operator-verified, append-only identity migration.
// Its credentials are used only in memory and never enter repository state.
package identitylink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/security"
)

const (
	maxBody          = 2 << 20
	pageSize         = 100
	maxUsers         = 10000
	operationTimeout = 60 * time.Second
	requestTimeout   = 10 * time.Second
)

var (
	errConfig   = errors.New("identity link: invalid configuration")
	errAdmin    = errors.New("identity link: admin request failed")
	errProof    = errors.New("identity link: invalid upstream identity proof")
	errConflict = errors.New("identity link: identity conflict or stale owner state")
	errMissing  = errors.New("identity link: legacy owner has no verified upstream identity")
)

// Config pins the realm and the legacy identity provider. HTTPClient may supply a
// trusted private CA; TLS verification and redirect rejection remain mandatory.
type Config struct {
	RealmIssuer, ClientID, ClientSecret, SourceIssuer, SourceProviderAlias string
	HTTPClient                                                             *http.Client
}

// Report contains counts only, so operator output cannot disclose identities or credentials.
// Linked counts verified proposed links during a dry run, and inserted links on apply.
type Report struct{ Scanned, Linked, AlreadyLinked, Unmatched int }

// Linker holds a short-lived Admin API access token, never the client secret.
type Linker struct {
	realmIssuer, sourceIssuer, providerAlias, adminURL, token string
	expires                                                   time.Time
	client                                                    *http.Client
}

type provider struct {
	Alias      string            `json:"alias"`
	ProviderID string            `json:"providerId"`
	Enabled    *bool             `json:"enabled"`
	Config     map[string]string `json:"config"`
}
type mapper struct {
	Alias  string            `json:"identityProviderAlias"`
	Mapper string            `json:"identityProviderMapper"`
	Config map[string]string `json:"config"`
}
type user struct {
	ID                     string `json:"id"`
	Enabled                *bool  `json:"enabled"`
	ServiceAccountClientID string `json:"serviceAccountClientId"`
}
type federatedIdentity struct {
	Provider string `json:"identityProvider"`
	UserID   string `json:"userId"`
}

// New authenticates the read-only operator client and validates the pinned
// provider. It never follows redirects or accepts an insecure realm URL.
func New(ctx context.Context, cfg Config) (*Linker, error) {
	realm, err := url.Parse(cfg.RealmIssuer)
	if err != nil || !cleanValue(cfg.RealmIssuer, 4096) || !httpsURL(realm) || strings.HasSuffix(realm.Path, "/") || realm.RawPath != "" || !cleanValue(cfg.ClientID, 512) || !cleanValue(cfg.ClientSecret, 8192) || !pathID(cfg.SourceProviderAlias) {
		return nil, errConfig
	}
	source, err := url.Parse(cfg.SourceIssuer)
	if err != nil || !cleanValue(cfg.SourceIssuer, 4096) || !httpsURL(source) || cfg.SourceIssuer == cfg.RealmIssuer {
		return nil, errConfig
	}
	marker := strings.LastIndex(realm.Path, "/realms/")
	if marker < 0 || !pathID(strings.TrimPrefix(realm.Path[marker:], "/realms/")) {
		return nil, errConfig
	}
	prefix, realmName := realm.Path[:marker], strings.TrimPrefix(realm.Path[marker:], "/realms/")
	if strings.Contains(prefix, "..") || strings.Contains(prefix, "//") {
		return nil, errConfig
	}
	hc := http.DefaultClient
	if cfg.HTTPClient != nil {
		hc = cfg.HTTPClient
	}
	client := *hc
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if tr, ok := transport.(*http.Transport); ok {
		if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
			return nil, errConfig
		}
		client.Transport = tr.Clone()
	}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errAdmin }
	if client.Timeout <= 0 || client.Timeout > requestTimeout {
		client.Timeout = requestTimeout
	}
	l := &Linker{realmIssuer: cfg.RealmIssuer, sourceIssuer: cfg.SourceIssuer, providerAlias: cfg.SourceProviderAlias, adminURL: realm.Scheme + "://" + realm.Host + prefix + "/admin/realms/" + url.PathEscape(realmName), client: &client}
	bounded, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cfg.ClientID}, "client_secret": {cfg.ClientSecret}}
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err = l.request(bounded, http.MethodPost, cfg.RealmIssuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()), &token); err != nil {
		return nil, err
	}
	if !cleanValue(token.AccessToken, 64<<10) || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn < 1 || token.ExpiresIn > 86400 {
		return nil, errAdmin
	}
	l.token = token.AccessToken
	l.expires = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	if err = l.verifyProvider(bounded); err != nil {
		return nil, err
	}
	return l, nil
}

func httpsURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(u.Host, "\r\n\t")
}

func cleanValue(v string, max int) bool {
	if v == "" || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func pathID(v string) bool {
	return cleanValue(v, 512) && v != "." && v != ".." && !strings.ContainsAny(v, "/\\?#%")
}

func (l *Linker) request(ctx context.Context, method, endpoint string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return errAdmin
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.Header.Set("Authorization", "Bearer "+l.token)
	}
	response, err := l.client.Do(req)
	if err != nil {
		return errAdmin
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errAdmin
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(b) > maxBody || !utf8.Valid(b) || !uniqueJSON(b) || json.Unmarshal(b, out) != nil {
		return errAdmin
	}
	return nil
}

func (l *Linker) verifyProvider(ctx context.Context) error {
	if !time.Now().Before(l.expires) {
		return errAdmin
	}
	endpoint := l.adminURL + "/identity-provider/instances/" + url.PathEscape(l.providerAlias)
	var p provider
	if err := l.request(ctx, http.MethodGet, endpoint, nil, &p); err != nil {
		return err
	}
	if p.Alias != l.providerAlias || p.ProviderID != "oidc" || p.Enabled == nil || !*p.Enabled || p.Config["issuer"] != l.sourceIssuer || p.Config["validateSignature"] != "true" || (p.Config["userIDClaim"] != "" && p.Config["userIDClaim"] != "sub") || p.Config["userIdClaim"] != "" {
		return errProof
	}
	var mappers []mapper
	if err := l.request(ctx, http.MethodGet, endpoint+"/mappers", nil, &mappers); err != nil {
		return err
	}
	if mappers == nil {
		return errProof
	}
	for _, m := range mappers {
		// LOCAL changes only the displayed local username. BROKER_ID rewrites the
		// upstream subject and must never authorize continuity of a legacy account.
		if m.Alias != l.providerAlias || m.Mapper != "oidc-username-idp-mapper" || (m.Config["target"] != "" && m.Config["target"] != "LOCAL") {
			return errProof
		}
	}
	return nil
}

// Link verifies every legacy owner's exact federated upstream subject before
// atomically adding aliases. Passing apply=false performs the same checks but
// changes no identities or audit events. No Admin API writes are performed.
func (l *Linker) Link(ctx context.Context, repo domain.Repository, apply bool) (Report, error) {
	report := Report{}
	if l == nil || repo == nil {
		return report, errConfig
	}
	bounded, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	owners := map[string]domain.User{}
	if err := repo.Transact(bounded, func(st *domain.State) error {
		for id, u := range st.Users {
			if u.Issuer == l.sourceIssuer {
				owners[id] = u
			}
		}
		if len(owners) > maxUsers {
			return errProof
		}
		return nil
	}); err != nil {
		return report, err
	}
	report.Scanned = len(owners)
	if err := l.verifyProvider(bounded); err != nil {
		return report, err
	}
	proofs, err := l.proofs(bounded)
	if err != nil {
		return report, err
	}
	if err = l.verifyProvider(bounded); err != nil {
		return report, err
	}
	proposed := map[string]string{}
	for id, u := range owners {
		sub, ok := proofs[u.Subject]
		if !ok {
			report.Unmatched++
			continue
		}
		proposed[id] = sub
	}
	if report.Unmatched > 0 {
		return report, errMissing
	}
	// Sorting produces stable audit ordering without exposing identity information.
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	err = repo.Transact(bounded, func(st *domain.State) error {
		current := 0
		for id, u := range st.Users {
			if u.Issuer == l.sourceIssuer {
				current++
				if original, ok := owners[id]; !ok || original != u {
					return errConflict
				}
			}
		}
		if current != len(owners) {
			return errConflict
		}
		linked, already := 0, 0
		pending := make([]domain.IdentityAlias, 0, len(ids))
		for _, id := range ids {
			u, exists := st.Users[id]
			if !exists || u != owners[id] {
				return errConflict
			}
			subject := proposed[id]
			for _, a := range st.IdentityAliases {
				if a.OwnerID == id && a.Issuer == l.realmIssuer && a.Subject != subject {
					return errConflict
				}
			}
			if existing, ok := domain.ResolveIdentity(st, l.realmIssuer, subject); ok {
				if existing.ID != id {
					return errConflict
				}
				already++
				continue
			}
			pending = append(pending, domain.IdentityAlias{Issuer: l.realmIssuer, Subject: subject, OwnerID: id})
			linked++
		}
		if apply {
			for _, a := range pending {
				st.IdentityAliases[domain.IdentityKey(a.Issuer, a.Subject)] = a
				st.Audits = append(st.Audits, domain.Audit{ID: security.ID(), At: st.Now, ActorType: "operator", ActorID: "identity-migration", SubjectID: a.OwnerID, Action: "owner.identity.linked", Outcome: "allowed"})
			}
		}
		report.Linked, report.AlreadyLinked = linked, already
		return nil
	})
	if err != nil {
		report.Linked = 0
		report.AlreadyLinked = 0
	}
	return report, err
}

// proofs returns exact upstream subject -> Keycloak subject bindings. Duplicate
// records are rejected even when they happen to repeat an identical subject.
func (l *Linker) proofs(ctx context.Context) (map[string]string, error) {
	result := map[string]string{}
	seen := map[string]bool{}
	for first := 0; first <= maxUsers; first += pageSize {
		endpoint := l.adminURL + "/users?" + url.Values{"first": {strconv.Itoa(first)}, "max": {strconv.Itoa(pageSize)}}.Encode()
		var users []user
		if err := l.request(ctx, http.MethodGet, endpoint, nil, &users); err != nil {
			return nil, err
		}
		if users == nil || len(users) > pageSize || len(seen)+len(users) > maxUsers {
			return nil, errProof
		}
		for _, listed := range users {
			if !pathID(listed.ID) || seen[listed.ID] {
				return nil, errProof
			}
			seen[listed.ID] = true
			endpoint = l.adminURL + "/users/" + url.PathEscape(listed.ID)
			var actual user
			if err := l.request(ctx, http.MethodGet, endpoint, nil, &actual); err != nil {
				return nil, err
			}
			if actual.ID != listed.ID || actual.Enabled == nil {
				return nil, errProof
			}
			var identities []federatedIdentity
			if err := l.request(ctx, http.MethodGet, endpoint+"/federated-identity", nil, &identities); err != nil {
				return nil, err
			}
			if identities == nil {
				return nil, errProof
			}
			providers := map[string]bool{}
			matched := ""
			for _, identity := range identities {
				if !pathID(identity.Provider) || !cleanValue(identity.UserID, 4096) || providers[identity.Provider] {
					return nil, errProof
				}
				providers[identity.Provider] = true
				if identity.Provider == l.providerAlias {
					matched = identity.UserID
				}
			}
			if matched != "" {
				if !*actual.Enabled || actual.ServiceAccountClientID != "" || len(identities) != 1 {
					return nil, errProof
				}
				if _, duplicate := result[matched]; duplicate {
					return nil, errProof
				}
				result[matched] = actual.ID
			}
		}
		if len(users) < pageSize {
			return result, nil
		}
	}
	return nil, errProof
}

// uniqueJSON rejects ambiguous repeated member names and excessive nesting before
// decoding a response into its representation. Unknown ordinary fields remain
// compatible with Keycloak's full Admin API responses.
func uniqueJSON(b []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(b))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 64 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delimiter {
		case '{':
			names := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return false
				}
				name, ok := key.(string)
				name = foldJSONName(name)
				if !ok || names[name] {
					return false
				}
				names[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

// encoding/json matches struct fields using Unicode simple folding, not just
// lowercase conversion (for example s, S and long-s are equivalent).
func foldJSONName(name string) string {
	return strings.Map(func(r rune) rune {
		minimum := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, name)
}
