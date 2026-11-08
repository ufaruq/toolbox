package main

import "testing"

func TestOptionalMCPConfigPinsOwnerTenantAndClients(t *testing.T) {
	load := func(values map[string]string) bool {
		cfg, err := loadMCPConfig(func(k string) string { return values[k] }, "https://tenant.okta.example", "owner-client", "http://127.0.0.1:8080")
		return err == nil && cfg != nil && cfg.OwnerIssuer == "https://tenant.okta.example" && cfg.Audience == "http://127.0.0.1:8080/mcp" && cfg.Clients["code-client"] == "Local agent"
	}
	valid := map[string]string{"TOOLBOX_MCP_ISSUER": "https://tenant.okta.example/oauth2/default", "TOOLBOX_MCP_CLIENTS": `{"code-client":"Local agent"}`}
	if !load(valid) {
		t.Fatal("valid local MCP configuration rejected")
	}
	for _, change := range []map[string]string{
		{"TOOLBOX_MCP_ISSUER": ""}, {"TOOLBOX_MCP_CLIENTS": ""},
		{"TOOLBOX_MCP_ISSUER": "https://other.okta.example/oauth2/default"},
		{"TOOLBOX_MCP_ISSUER": "https://tenant.okta.example"},
		{"TOOLBOX_MCP_CLIENTS": `{"code-client":"First","code-client":"Second"}`},
		{"TOOLBOX_MCP_CLIENTS": `{"owner-client":"Owner login"}`},
		{"TOOLBOX_MCP_CLIENTS": `{"http://127.0.0.1:8080/mcp":"Audience"}`},
		{"TOOLBOX_MCP_CLIENTS": `{}`},
	} {
		env := copySettings(valid)
		for k, v := range change {
			env[k] = v
		}
		if load(env) {
			t.Fatal("unsafe/incomplete MCP config accepted")
		}
	}
	cfg, err := loadMCPConfig(func(string) string { return "" }, "https://tenant.okta.example", "owner-client", "http://127.0.0.1:8080")
	if err != nil || cfg != nil {
		t.Fatal("existing Workspace configuration must keep MCP optional")
	}
}

func TestKeycloakMCPConfiguration(t *testing.T) {
	values := map[string]string{"TOOLBOX_IDENTITY_PROVIDER": "keycloak", "TOOLBOX_MCP_ISSUER": "https://login.example/realms/toolbox", "TOOLBOX_MCP_CLIENTS": `{"code-client":"Local agent"}`}
	get := func(k string) string { return values[k] }
	cfg, err := loadMCPConfig(get, "https://login.example/realms/toolbox", "owner-client", "http://127.0.0.1:8080")
	if err != nil || cfg == nil {
		t.Fatalf("Keycloak realm rejected: %v", err)
	}
	for _, issuer := range []string{"https://login.example/realms/other", "https://login.example", "https://other.example/realms/toolbox", "http://login.example/realms/toolbox"} {
		values["TOOLBOX_MCP_ISSUER"] = issuer
		if _, err = loadMCPConfig(get, "https://login.example/realms/toolbox", "owner-client", "http://127.0.0.1:8080"); err == nil {
			t.Fatalf("unbound Keycloak issuer accepted: %s", issuer)
		}
	}
}

func TestUnknownIdentityBackendRejected(t *testing.T) {
	_, err := loadMCPConfig(func(k string) string {
		if k == "TOOLBOX_IDENTITY_PROVIDER" {
			return "oidc-anything"
		}
		return ""
	}, "https://tenant.okta.example", "owner-client", "http://127.0.0.1:8080")
	if err == nil {
		t.Fatal("unknown backend silently disabled MCP")
	}
}
