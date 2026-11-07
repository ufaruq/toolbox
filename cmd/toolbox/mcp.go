package main

import (
	"errors"
	"strings"

	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/strict"
)

func loadMCPConfig(getenv func(string) string, ownerIssuer, ownerClientID, origin string) (*identity.AccessConfig, error) {
	provider, err := loadIdentityProvider(getenv)
	if err != nil {
		return nil, err
	}
	issuer, raw := getenv("TOOLBOX_MCP_ISSUER"), getenv("TOOLBOX_MCP_CLIENTS")
	if issuer == "" && raw == "" {
		return nil, nil
	}
	invalid := errors.New("invalid MCP tenant/client configuration")
	bound := identity.ValidOwnerBinding(ownerIssuer, issuer, false)
	if provider == "keycloak" {
		bound = identity.ValidKeycloakOwnerBinding(ownerIssuer, issuer, false)
	}
	if !bound || len(raw) > 65536 {
		return nil, invalid
	}
	var clients map[string]string
	if strict.Decode([]byte(raw), &clients) != nil || len(clients) == 0 || len(clients) > 128 {
		return nil, invalid
	}
	for id, label := range clients {
		if id == ownerClientID || id == origin+"/mcp" || id == "" || label == "" || len(id) > 256 || len(label) > 256 || strings.TrimSpace(id) != id || strings.TrimSpace(label) != label || strings.ContainsAny(id+label, "\x00\r\n") {
			return nil, invalid
		}
	}
	return &identity.AccessConfig{Provider: provider, Issuer: issuer, OwnerIssuer: ownerIssuer, Audience: origin + "/mcp", OwnerClientID: ownerClientID, Clients: clients}, nil
}
