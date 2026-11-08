package keycloaktest

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUpstreamsKeepEqualEmailSubjectsSeparateAndVerifyPKCE(t *testing.T) {
	config := Config{OktaIssuer: "https://upstream.example.test/okta", GoogleIssuer: "https://upstream.example.test/google", OktaClientID: "okta-client", OktaClientSecret: "okta-secret", GoogleClientID: "google-client", GoogleClientSecret: "google-secret"}
	handler, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	fixture := handler.(*fixture)
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	var emails []string
	for _, alias := range []string{"okta", "google"} {
		provider := fixture.providers[alias]
		redirect := "https://keycloak.example.test/realms/toolbox/broker/" + alias + "/endpoint"
		query := url.Values{"client_id": {provider.clientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid profile email"}, "state": {"test-state"}, "nonce": {"test-nonce"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}
		authorize := func() string {
			t.Helper()
			response, err := client.Get(server.URL + "/" + alias + "/v1/authorize?" + query.Encode())
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusFound {
				t.Fatalf("authorize status %d", response.StatusCode)
			}
			location, err := response.Location()
			if err != nil || location.Query().Get("state") != "test-state" || location.Query().Get("code") == "" {
				t.Fatal("missing authorization callback")
			}
			return location.Query().Get("code")
		}
		exchange := func(code, codeVerifier string, want int) map[string]any {
			t.Helper()
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {codeVerifier}}
			request, _ := http.NewRequest(http.MethodPost, server.URL+"/"+alias+"/v1/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth(provider.clientID, provider.secret)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != want {
				t.Fatalf("token status %d, want %d", response.StatusCode, want)
			}
			var result map[string]any
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			return result
		}
		badCode := authorize()
		exchange(badCode, "wrong-verifier", http.StatusBadRequest)
		exchange(badCode, verifier, http.StatusBadRequest)
		code := authorize()
		tokens := exchange(code, verifier, http.StatusOK)
		exchange(code, verifier, http.StatusBadRequest)
		parts := strings.Split(tokens["id_token"].(string), ".")
		if len(parts) != 3 {
			t.Fatal("malformed ID token")
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		signedDigest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&fixture.key.PublicKey, crypto.SHA256, signedDigest[:], signature); err != nil {
			t.Fatal("invalid ID token signature")
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		if claims["iss"] != provider.issuer || claims["aud"] != provider.clientID || claims["sub"] != alias+"-subject" || claims["nonce"] != "test-nonce" || claims["email_verified"] != true {
			t.Fatal("incorrect upstream identity")
		}
		emails = append(emails, claims["email"].(string))
		for _, target := range []string{alias, map[string]string{"okta": "google", "google": "okta"}[alias]} {
			request, _ := http.NewRequest(http.MethodGet, server.URL+"/"+target+"/v1/userinfo", nil)
			request.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			want := http.StatusOK
			if target != alias {
				want = http.StatusUnauthorized
			}
			if response.StatusCode != want {
				t.Fatal("userinfo token crossed provider boundary")
			}
		}
	}
	if emails[0] != emails[1] {
		t.Fatal("fixture must deliberately reuse the email")
	}
}
