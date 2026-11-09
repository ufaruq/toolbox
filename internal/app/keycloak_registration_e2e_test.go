package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/testutil/keycloaktest"
)

func registrationRequest(t *testing.T, infra *keycloaktest.Harness, method, endpoint, token string, input map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(input)
	req, _ := http.NewRequest(method, endpoint, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := infra.Client.Do(req)
	if err != nil {
		t.Fatal("dynamic registration request failed")
	}
	defer resp.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result)
	return resp.StatusCode, result
}
func keycloakDynamicOnboarding(t *testing.T, ctx context.Context, h *harness, infra *keycloaktest.Harness, origin, ownerClient, staticClient string) {
	t.Helper()
	endpoint := infra.RealmIssuer + "/clients-registrations/openid-connect"
	response, err := infra.Client.Get(infra.RealmIssuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal("discovery failed")
	}
	var metadata map[string]any
	_ = json.NewDecoder(response.Body).Decode(&metadata)
	response.Body.Close()
	if metadata["registration_endpoint"] != endpoint {
		t.Fatal("registration not discoverable")
	}
	base := func() map[string]any {
		return map[string]any{"client_name": "Untrusted display label", "redirect_uris": []string{origin + "/keycloak-test/callback"}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": "openid mcp"}
	}
	// The realm import retains native scopes for builtin clients. Until the
	// separate administrator setup, inherited defaults must fail closed.
	for _, withScope := range []bool{true, false} {
		input := base()
		if !withScope {
			delete(input, "scope")
		}
		statusBefore, _ := registrationRequest(t, infra, "POST", endpoint, "", input)
		if statusBefore != 403 {
			t.Fatalf("unconfigured realm did not fail closed: %d", statusBefore)
		}
	}
	adminToken := keycloakRestrictRealmDefaults(t, infra)
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"wildcard", "redirect_uris", []string{origin + "/*"}},
		{"foreign-host", "redirect_uris", []string{"https://untrusted.example/callback"}},
		{"dns-loopback", "redirect_uris", []string{"http://127.0.0.1.nip.io/callback"}},
		{"confidential", "token_endpoint_auth_method", "client_secret_basic"},
		{"remote-sector", "sector_identifier_uri", "https://untrusted.example/sector"},
		{"privileged-scope", "scope", "openid mcp roles offline_access"},
		{"device", "grant_types", []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"}},
		{"ciba", "grant_types", []string{"authorization_code", "urn:openid:params:grant-type:ciba"}},
		{"exchange", "grant_types", []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"}},
		{"uma", "grant_types", []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:uma-ticket"}},
	} {
		before := keycloakClientCount(t, infra, adminToken)
		input := base()
		input[tc.key] = tc.value
		status, _ := registrationRequest(t, infra, "POST", endpoint, "", input)
		if tc.name == "uma" {
			if status != 500 {
				t.Fatalf("unexpected native public UMA registration status=%d", status)
			}
			t.Log("pinned Keycloak rejects public UMA metadata with HTTP500; no client is retained")
		} else if status < 400 || status >= 500 {
			t.Fatalf("unsafe %s creation: status=%d", tc.name, status)
		}
		if keycloakClientCount(t, infra, adminToken) != before {
			t.Fatalf("rejected %s registration retained a client", tc.name)
		}
		status, client := registrationRequest(t, infra, "POST", endpoint, "", base())
		if status != 201 {
			t.Fatalf("safe DCR setup rejected: status=%d error=%v description=%v", status, client["error"], client["error_description"])
		}
		input = base()
		input["client_id"] = client["client_id"]
		status, updated := registrationRequest(t, infra, "PUT", client["registration_client_uri"].(string), client["registration_access_token"].(string), input)
		if status != 200 {
			t.Fatalf("safe DCR update rejected: status=%d error=%v", status, updated["error"])
		}
		client = updated
		input[tc.key] = tc.value
		status, unsafeResult := registrationRequest(t, infra, "PUT", client["registration_client_uri"].(string), client["registration_access_token"].(string), input)
		if tc.name == "uma" {
			// OIDC updates ignore authorization-services metadata; assert unchanged
			// grants below, rather than claiming the request itself is rejected.
			if status != 200 {
				t.Fatalf("native UMA update: %d", status)
			}
			// A successful update rotates its registration token.
			client["registration_access_token"] = unsafeResult["registration_access_token"]
		} else if status < 400 || status >= 500 {
			t.Fatalf("unsafe %s update: status=%d", tc.name, status)
		}
		status, after := registrationRequest(t, infra, "GET", client["registration_client_uri"].(string), client["registration_access_token"].(string), nil)
		if status != 200 {
			t.Fatalf("rejected %s update invalidated registration: %d", tc.name, status)
		}
		beforeJSON, _ := json.Marshal(client["grant_types"])
		afterJSON, _ := json.Marshal(after["grant_types"])
		if !bytes.Equal(beforeJSON, afterJSON) {
			t.Fatalf("rejected %s update changed grant types", tc.name)
		}
		beforeJSON, _ = json.Marshal(client["redirect_uris"])
		afterJSON, _ = json.Marshal(after["redirect_uris"])
		if !bytes.Equal(beforeJSON, afterJSON) {
			t.Fatalf("rejected %s update changed callbacks", tc.name)
		}
	}
	status, client := registrationRequest(t, infra, "POST", endpoint, "", base())
	if status != 201 {
		t.Fatalf("public registration failed: %d", status)
	}
	clientID := client["client_id"].(string)
	// Registration alone never grants an Agent or creates a dashboard candidate.
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		if len(st.CallerCandidates) != 0 {
			t.Error("registration created candidate without verified owner token")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	dynamic, err := identity.NewAccess(ctx, identity.AccessConfig{Provider: "keycloak", Issuer: infra.RealmIssuer, OwnerIssuer: infra.RealmIssuer, Audience: origin + "/mcp", OwnerClientID: ownerClient, Clients: map[string]string{staticClient: "Static"}, DynamicClientOnboarding: true, HTTPClient: infra.Client})
	if err != nil {
		t.Fatal(err)
	}
	h.api.Identity = dynamic
	token, _ := keycloakTokens(t, infra, origin, clientID, "okta", "openid mcp")
	// Static verifier remains fail-closed even while the explicit onboarding path works.
	if _, err := dynamic.VerifyAccess(ctx, token); err == nil {
		t.Fatal("static verifier admitted dynamic client")
	}
	keycloakMCPDenied(t, ctx, h, infra, token)
	pending := h.call("GET", "/v1/callers", nil, "", "", 200)["pending_callers"].([]any)
	if len(pending) != 1 {
		t.Fatalf("pending clients=%d", len(pending))
	}
	candidate := pending[0].(map[string]any)
	if candidate["client_id"] != clientID || candidate["status"] != "pending" {
		t.Fatal("wrong pending identity")
	}
	profile := h.call("POST", "/v1/callers/pending/"+candidate["id"].(string)+"/approve", map[string]any{"label": "My dynamic agent", "tools": []string{domain.Tool}, "duration_seconds": 3600}, "", "", 201)
	sess := keycloakMCP(t, ctx, h, infra, token)
	acceptanceDenied(t, ctx, h, sess, "google_drive_read_document_v1", map[string]any{"grant_id": "unknown", "file_id": "doc-A"})
	request := acceptanceRequest(t, ctx, h, sess, "doc-A")
	grant := acceptanceApprove(t, ctx, h, sess, request, clientID, "doc-A")
	acceptanceRead(t, ctx, h, sess, grant, "doc-A")
	h.call("POST", "/v1/grants/"+grant+"/revoke", map[string]any{}, "", "", 200)
	acceptanceDenied(t, ctx, h, sess, "google_drive_read_document_v1", map[string]any{"grant_id": grant, "file_id": "doc-A"})
	h.call("POST", "/v1/callers/"+profile["id"].(string)+"/disable", map[string]any{}, "", "", 200)
	keycloakMCPDenied(t, ctx, h, infra, token)
	// A separate upstream user cannot inherit this owner's client or documents.
	other, _ := keycloakTokens(t, infra, origin, clientID, "google", "openid mcp")
	keycloakMCPDenied(t, ctx, h, infra, other)
	// Public clients cannot exercise client credentials even if metadata asks for it.
	service := base()
	service["grant_types"] = []string{"authorization_code", "client_credentials"}
	status, serviceClient := registrationRequest(t, infra, "POST", endpoint, "", service)
	if status == 201 {
		resp, err := infra.Client.PostForm(infra.RealmIssuer+"/protocol/openid-connect/token", url.Values{"client_id": {serviceClient["client_id"].(string)}, "grant_type": {"client_credentials"}, "scope": {"mcp"}})
		if err != nil {
			t.Fatal("service account negative test")
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatal("public service account token issued")
		}
	} else if status >= 500 {
		t.Fatal("service metadata caused server error")
	}
	serviceUpdate := base()
	serviceUpdate["client_id"] = clientID
	serviceUpdate["grant_types"] = []string{"authorization_code", "client_credentials"}
	status, _ = registrationRequest(t, infra, "PUT", client["registration_client_uri"].(string), client["registration_access_token"].(string), serviceUpdate)
	if status != 400 {
		t.Fatalf("service account update not rejected: %d", status)
	}
	// Native default representation must not allow mapper injection or PKCE downgrade.
	defaultURL := infra.RealmIssuer + "/clients-registrations/default/" + url.PathEscape(clientID)
	for _, change := range []map[string]any{
		{"protocolMappers": []any{map[string]any{"name": "forge-sub", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper", "config": map[string]string{"claim.name": "sub", "claim.value": "owner", "access.token.claim": "true"}}}},
		{"attributes": map[string]string{"pkce.code.challenge.method": "plain"}},
	} {
		input := map[string]any{"clientId": clientID, "publicClient": true, "protocol": "openid-connect", "redirectUris": []string{origin + "/keycloak-test/callback"}, "fullScopeAllowed": false, "consentRequired": true, "defaultClientScopes": []string{"basic"}, "optionalClientScopes": []string{"mcp"}}
		for k, v := range change {
			input[k] = v
		}
		status, result := registrationRequest(t, infra, "PUT", defaultURL, client["registration_access_token"].(string), input)
		if _, downgrade := change["attributes"]; downgrade {
			// Native auto-configuration normalizes the attempted downgrade to S256.
			attrs, _ := result["attributes"].(map[string]any)
			if status != 200 || attrs["pkce.code.challenge.method"] != "S256" {
				t.Fatalf("PKCE downgrade was not normalized: %d", status)
			}
		} else if status < 400 || status >= 500 {
			t.Fatalf("unsafe default mapper update: %d", status)
		}
	}
	// Pairwise subject choice derives a different identity; it must fail closed.
	pairwise := base()
	pairwise["subject_type"] = "pairwise"
	status, pairClient := registrationRequest(t, infra, "POST", endpoint, "", pairwise)
	if status == 201 {
		pairToken, _ := keycloakTokens(t, infra, origin, pairClient["client_id"].(string), "okta", "openid mcp")
		keycloakMCPDenied(t, ctx, h, infra, pairToken)
	} else if status >= 500 {
		t.Fatal("pairwise registration server error")
	}
	// Missing/plain PKCE never reaches the upstream user login.
	for _, method := range []string{"", "plain"} {
		query := url.Values{"client_id": {clientID}, "redirect_uri": {origin + "/keycloak-test/callback"}, "response_type": {"code"}, "scope": {"openid mcp"}}
		if method != "" {
			query.Set("code_challenge_method", method)
			query.Set("code_challenge", strings.Repeat("v", 43))
		}
		browser := keycloakBrowser(t, infra)
		resp, err := browser.Get(infra.RealmIssuer + "/protocol/openid-connect/auth?" + query.Encode())
		if err != nil {
			t.Fatal("PKCE denial request")
		}
		resp.Body.Close()
		if resp.StatusCode < 400 && resp.Request.URL.Query().Get("error") == "" {
			t.Fatalf("insecure PKCE accepted status=%d", resp.StatusCode)
		}
	}
	if err := h.repo.Transact(ctx, func(st *domain.State) error {
		if len(st.CallerCandidates) != 1 {
			t.Error("unlinked/pairwise identity enqueued a candidate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The native quota is sequential, not an atomic concurrent reservation.
	remaining := 128 - keycloakClientCount(t, infra, adminToken)
	if remaining < 1 || remaining > 128 {
		t.Fatal("unexpected client quota baseline")
	}
	for n := 0; n <= remaining; n++ {
		status, _ := registrationRequest(t, infra, "POST", endpoint, "", base())
		if n < remaining && status != 201 || n == remaining && status != 403 {
			t.Fatalf("registration quota at %d remaining: %d", remaining-n, status)
		}
	}
	if keycloakClientCount(t, infra, adminToken) != 128 {
		t.Fatal("native sequential client quota not enforced")
	}
	t.Log("real dynamic registration: hardened create/update, pending owner approval, separate document grant/read/revoke, owner isolation and PKCE denial passed")
}

// Mirrors the documented administrator setup using a temporary master user in
// the isolated test container. No production service-account privileges change.
func keycloakRestrictRealmDefaults(t *testing.T, infra *keycloaktest.Harness) string {
	t.Helper()
	response, err := infra.Client.PostForm(infra.Broker+"/realms/master/protocol/openid-connect/token", url.Values{"client_id": {"admin-cli"}, "grant_type": {"password"}, "username": {"fixture-admin"}, "password": {infra.Credentials.Bootstrap}})
	if err != nil {
		t.Fatal("authenticate synthetic setup administrator")
	}
	var tokens struct {
		Access string `json:"access_token"`
	}
	err = json.NewDecoder(response.Body).Decode(&tokens)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || tokens.Access == "" {
		t.Fatal("synthetic administrator token unavailable")
	}
	admin := infra.Broker + "/admin/realms/toolbox-e2e"
	do := func(method, path string) *http.Response {
		req, _ := http.NewRequest(method, admin+path, nil)
		req.Header.Set("Authorization", "Bearer "+tokens.Access)
		resp, err := infra.Client.Do(req)
		if err != nil {
			t.Fatal("scope setup request")
		}
		return resp
	}
	for _, path := range []string{"/default-default-client-scopes", "/default-optional-client-scopes"} {
		resp := do("GET", path)
		var scopes []struct{ ID, Name string }
		err := json.NewDecoder(resp.Body).Decode(&scopes)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			t.Fatal("read inherited scopes")
		}
		for _, scope := range scopes {
			if path == "/default-default-client-scopes" && scope.Name == "basic" || path == "/default-optional-client-scopes" && scope.Name == "mcp" {
				continue
			}
			resp = do("DELETE", path+"/"+url.PathEscape(scope.ID))
			resp.Body.Close()
			if resp.StatusCode != 204 {
				t.Fatal("restrict inherited scope")
			}
		}
	}
	// Removing realm defaults must preserve assignments on existing builtin clients.
	resp := do("GET", "/clients?clientId=security-admin-console")
	var clients []struct{ ID string }
	err = json.NewDecoder(resp.Body).Decode(&clients)
	resp.Body.Close()
	if err != nil || len(clients) != 1 {
		t.Fatal("read builtin administrator client")
	}
	resp = do("GET", "/clients/"+clients[0].ID+"/default-client-scopes")
	var scopes []struct{ Name string }
	err = json.NewDecoder(resp.Body).Decode(&scopes)
	resp.Body.Close()
	if err != nil {
		t.Fatal("read preserved builtin scopes")
	}
	found := map[string]bool{}
	for _, scope := range scopes {
		found[scope.Name] = true
	}
	if !found["basic"] || !found["roles"] {
		t.Fatal("builtin scope assignments lost")
	}

	resp = do("GET", "/client-policies/policies")
	var policySet map[string]any
	err = json.NewDecoder(resp.Body).Decode(&policySet)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("read setup gate")
	}
	foundGate := false
	for _, item := range policySet["policies"].([]any) {
		policy := item.(map[string]any)
		if policy["name"] == "toolbox-dcr-setup-required" {
			policy["enabled"] = false
			foundGate = true
		}
	}
	if !foundGate {
		t.Fatal("missing setup admission gate")
	}
	raw, _ := json.Marshal(policySet)
	req, _ := http.NewRequest("PUT", admin+"/client-policies/policies", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+tokens.Access)
	req.Header.Set("Content-Type", "application/json")
	resp, err = infra.Client.Do(req)
	if err != nil {
		t.Fatal("open setup admission gate")
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("open setup gate status=%d", resp.StatusCode)
	}
	return tokens.Access
}
func keycloakClientCount(t *testing.T, infra *keycloaktest.Harness, token string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", infra.Broker+"/admin/realms/toolbox-e2e/clients?first=0&max=200", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := infra.Client.Do(req)
	if err != nil {
		t.Fatal("count test realm clients")
	}
	defer resp.Body.Close()
	var clients []struct{ ID string }
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&clients) != nil {
		t.Fatal("read test client count")
	}
	return len(clients)
}
