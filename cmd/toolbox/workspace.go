package main

import (
	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/tokens"
)

type workspaceSecrets interface {
	oauth.SecretStore
	tokens.SecretStore
}

// Runtime construction always uses real fixed-endpoint providers. No runtime
// setting substitutes a fixture transport or identity here.
func newWorkspaceIntegration(cfg runtimeConfig, repo domain.Repository, secrets workspaceSecrets) (*app.Integration, error) {
	provider, err := oauth.NewGoogleProvider(oauth.GoogleConfig{
		ClientID: cfg.workspace.googleClientID, ClientSecret: cfg.workspace.googleClientSecret,
		CallbackURL: cfg.origin + "/oauth/callback", AllowLoopbackHTTP: true,
		PKCEValidated: true, IdentityScopes: true, // loadConfig requires the actual-client gate.
	})
	if err != nil {
		return nil, err
	}
	flow, err := oauth.NewIndependentGoogleService(repo, secrets, provider)
	if err != nil {
		return nil, err
	}
	return &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: repo, Secrets: secrets, Provider: provider}, Drive: gdrive.New()}, nil
}
