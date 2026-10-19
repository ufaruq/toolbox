// Toolbox supports the synthetic fixture and local owner OIDC sign-in.
// Neither mode is a public production deployment.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/ownerlogin"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func main() {
	if e := run(); e != nil {
		log.Print("Toolbox startup or shutdown failed; check documented configuration and dependency availability.")
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 {
		if len(os.Args) == 2 && os.Args[1] == "google-pkce-check" {
			return runGooglePKCECheck()
		}
		return errors.New("unknown command")
	}
	cfg, e := loadConfig(os.Getenv)
	if e != nil {
		return e
	}
	if cfg.mode == "oidc-local" || cfg.mode == "workspace-local" {
		return runOIDCLocal(cfg)
	}
	addr := cfg.addr
	origin := "http://" + addr
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var repo domain.Repository = store.NewMemory()
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		p, e := store.OpenPostgres(ctx, dsn)
		if e != nil {
			return e
		}
		defer p.Close()
		if e = p.Migrate(ctx); e != nil {
			return e
		}
		repo = p
	}
	var secrets oauth.SecretStore = tokens.NewMemorySecretStore()
	if address := os.Getenv("OPENBAO_ADDR"); address != "" {
		bao, e := tokens.NewOpenBaoFixture(tokens.OpenBaoConfig{Address: address, Mount: "secret", Token: os.Getenv("OPENBAO_TOKEN")})
		if e != nil {
			return e
		}
		secrets = bao
	}
	provider, e := oauth.NewFixtureProvider("fixture-client", origin+"/oauth/callback")
	if e != nil {
		return e
	}
	flow, e := oauth.NewService(repo, secrets, provider)
	if e != nil {
		return e
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	signer, e := security.NewSigner(origin, "fixture-ephemeral", private)
	if e != nil {
		return e
	}
	pepper := make([]byte, 32)
	if _, e = rand.Read(pepper); e != nil {
		return e
	}
	integration := &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: repo, Secrets: secrets, Provider: provider}, Drive: gdrive.NewFixture(&app.FixtureDrive{}), Fixture: provider}
	api, e := server.New(server.Config{Repository: repo, Signer: signer, Pepper: pepper, Origin: origin, Fixture: true, Readiness: func(ctx context.Context) error {
		if e := repo.Ping(ctx); e != nil {
			return e
		}
		return secrets.(interface{ Ping(context.Context) error }).Ping(ctx)
	}}, integration)
	if e != nil {
		return e
	}
	srv := &http.Server{Addr: addr, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	stopped := make(chan error, 1)
	go func() { stopped <- srv.ListenAndServe() }()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jobCtx, c := context.WithTimeout(ctx, 20*time.Second)
				_ = api.CleanupOnce(jobCtx)
				c()
			}
		}
	}()
	log.Printf("Toolbox fixture UI: %s (mock identity, mock Google; no live provider validation)", origin)
	select {
	case <-ctx.Done():
		shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		return srv.Shutdown(shutdown)
	case e := <-stopped:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
}

func runOIDCLocal(cfg runtimeConfig) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	repo, err := store.OpenPostgres(ctx, cfg.databaseURL)
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		return err
	}
	secrets, err := tokens.NewOpenBaoFixture(tokens.OpenBaoConfig{Address: cfg.baoAddr, Mount: "secret", Token: cfg.baoToken})
	if err != nil {
		return err
	}
	if err = secrets.Ping(ctx); err != nil {
		return err
	}
	callback := cfg.origin + "/auth/oidc/callback"
	provider, err := ownerlogin.NewProvider(ctx, ownerlogin.ProviderConfig{Issuer: cfg.oidcIssuer, ClientID: cfg.oidcClientID, ClientSecret: cfg.oidcClientSecret, RedirectURI: callback}, nil)
	if err != nil {
		return err
	}
	login, err := ownerlogin.NewService(repo, secrets, provider, ownerlogin.ServiceConfig{Issuer: cfg.oidcIssuer, ClientID: cfg.oidcClientID, RedirectURI: callback, Pepper: cfg.pepper})
	if err != nil {
		return err
	}
	serverConfig := server.Config{Repository: repo, Pepper: cfg.pepper, Origin: cfg.origin, OwnerOnly: true, OwnerLogin: login, Readiness: func(ctx context.Context) error {
		if err := repo.Ping(ctx); err != nil {
			return err
		}
		return secrets.Ping(ctx)
	}}
	var integration *app.Integration
	if cfg.mode == "workspace-local" {
		integration, err = newWorkspaceIntegration(cfg, repo, secrets)
		if err != nil {
			return err
		}
		serverConfig.Signer, err = security.NewSigner(cfg.origin, cfg.workspace.signingKeyID, ed25519.NewKeyFromSeed(cfg.workspace.signingSeed))
		if err != nil {
			return err
		}
		serverConfig.OwnerOnly, serverConfig.WorkspaceLocal = false, true
		serverConfig.SessionPepper, serverConfig.Pepper = cfg.pepper, cfg.workspace.credentialPepper
		serverConfig.Picker = server.PickerConfig{APIKey: cfg.workspace.pickerAPIKey, ProjectNumber: cfg.workspace.projectNumber}
	}
	var providerBoundary server.Integration
	if integration != nil {
		providerBoundary = integration
	}
	api, err := server.New(serverConfig, providerBoundary)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.addr, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	stopped := make(chan error, 1)
	go func() { stopped <- srv.ListenAndServe() }()
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupCtx, stop := context.WithTimeout(ctx, 10*time.Second)
				if login.Cleanup(cleanupCtx) != nil {
					log.Print("Owner login cleanup deferred; check dependency availability.")
				}
				if integration != nil && api.CleanupOnce(cleanupCtx) != nil {
					log.Print("Google connection cleanup deferred; check dependency availability.")
				}
				stop()
			}
		}
	}()
	if cfg.mode == "workspace-local" {
		log.Printf("Toolbox local Workspace: %s (real providers; live acceptance must be recorded)", cfg.origin)
	} else {
		log.Printf("Toolbox local owner sign-in: %s (Google and agent operations are disabled)", cfg.origin)
	}
	select {
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		err = srv.Shutdown(shutdown)
	case err = <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	cancel()
	<-cleanupDone
	return err
}
