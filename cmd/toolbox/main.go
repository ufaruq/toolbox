// Toolbox serves an explicit local fixture or a validated hosted deployment.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/domain"
	"github.com/ufaruq/toolbox/internal/identity"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/tokens"
)

func main() {
	if err := run(); err != nil {
		log.Print("Toolbox startup or shutdown failed; check documented configuration and dependency availability.")
		os.Exit(1)
	}
}
func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCommand(ctx, os.Args[1:], os.Getenv)
}
func runCommand(ctx context.Context, args []string, getenv func(string) string) error {
	if len(args) > 0 {
		if len(args) != 1 {
			return errRuntimeConfig
		}
		switch args[0] {
		case "healthcheck":
			return healthcheck(ctx, getenv("TOOLBOX_ADDR"))
		case "migrate":
			mode := getenv("TOOLBOX_MODE")
			dsn := getenv("DATABASE_URL")
			if (mode != "hosted" && mode != "fixture") || !validDatabaseURL(dsn, mode == "hosted") {
				return errRuntimeConfig
			}
			bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			p, err := store.OpenPostgres(bounded, dsn)
			if err != nil {
				return err
			}
			defer p.Close()
			return p.Migrate(bounded)
		default:
			return errRuntimeConfig
		}
	}
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	var repo domain.Repository
	var secrets oauth.SecretStore
	if cfg.Mode == "fixture" {
		repo = store.NewMemory()
		secrets = tokens.NewMemorySecretStore()
	}
	if cfg.DatabaseURL != "" {
		p, err := store.OpenPostgres(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer p.Close()
		if cfg.Mode == "fixture" {
			if err := p.Migrate(ctx); err != nil {
				return err
			}
		}
		repo = p
	}
	if cfg.Bao.Address != "" {
		var bao *tokens.OpenBao
		if cfg.Mode == "fixture" {
			bao, err = tokens.NewOpenBaoFixture(cfg.Bao)
		} else {
			bao, err = tokens.NewOpenBao(cfg.Bao)
		}
		if err != nil {
			return err
		}
		secrets = bao
	}
	var id server.Identity
	if cfg.Mode == "hosted" {
		bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err = checkRuntimeDependencies(bounded, repo, secrets); err == nil {
			id, err = identity.New(bounded, cfg.Identity)
		}
		cancel()
		if err != nil {
			return err
		}
	}
	api, err := newAPI(cfg, repo, secrets, id)
	if err != nil {
		return err
	}
	return serve(ctx, cfg, api)
}
func newAPI(cfg runtimeConfig, repo domain.Repository, secrets oauth.SecretStore, id server.Identity) (*server.Server, error) {
	var integration server.Integration = app.UnavailableIntegration{}
	var private ed25519.PrivateKey
	pepper := cfg.Pepper
	if cfg.Mode == "fixture" {
		provider, err := oauth.NewFixtureProvider("fixture-client", cfg.Origin+"/oauth/callback")
		if err != nil {
			return nil, err
		}
		flow, err := oauth.NewService(repo, secrets, provider)
		if err != nil {
			return nil, err
		}
		integration = &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: repo, Secrets: secrets, Provider: provider}, Drive: gdrive.NewFixture(&app.FixtureDrive{}), Fixture: provider}
		_, private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pepper = make([]byte, 32)
		if _, err = rand.Read(pepper); err != nil {
			return nil, err
		}
		cfg.KeyID = "fixture-ephemeral"
	} else {
		if cfg.Mode != "hosted" || len(cfg.SigningSeed) != ed25519.SeedSize || len(pepper) != 32 || id == nil {
			return nil, errRuntimeConfig
		}
		private = ed25519.NewKeyFromSeed(cfg.SigningSeed)
	}
	signer, err := security.NewSigner(cfg.Origin, cfg.KeyID, private)
	if err != nil {
		return nil, err
	}
	return server.New(server.Config{Repository: repo, Signer: signer, Pepper: pepper, Origin: cfg.Origin, Fixture: cfg.Mode == "fixture", Identity: id, LoginSecrets: secrets, Readiness: func(ctx context.Context) error {
		return checkRuntimeDependencies(ctx, repo, secrets)
	}}, integration)
}

// A successful connection alone does not prove that the runtime schema exists.
// The reference adapter's bounded snapshot transaction checks every required table.
func checkRuntimeDependencies(ctx context.Context, repo domain.Repository, secrets oauth.SecretStore) error {
	if schema, ok := repo.(interface{ CheckSchema(context.Context) error }); ok {
		if err := schema.CheckSchema(ctx); err != nil {
			return err
		}
	}
	if err := repo.Transact(ctx, func(*domain.State) error { return nil }); err != nil {
		return err
	}
	if p, ok := secrets.(interface{ Ping(context.Context) error }); ok {
		return p.Ping(ctx)
	}
	return errors.New("secret store readiness unavailable")
}
func serve(ctx context.Context, cfg runtimeConfig, api *server.Server) error {
	srv := &http.Server{Addr: cfg.Addr, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	stopped := make(chan error, 1)
	go func() { stopped <- srv.ListenAndServe() }()
	jobs, cancelJobs := context.WithCancel(ctx)
	defer cancelJobs()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-jobs.Done():
				return
			case <-ticker.C:
				jobCtx, cancel := context.WithTimeout(jobs, 20*time.Second)
				_ = api.CleanupOnce(jobCtx)
				cancel()
			}
		}
	}()
	log.Printf("Toolbox %s UI: %s", cfg.Mode, cfg.Origin)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case err := <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
func healthcheck(ctx context.Context, addr string) error {
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if !validBind(addr, false) {
		return errRuntimeConfig
	}
	host, port, _ := net.SplitHostPort(addr)
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" {
		host = "::1"
	}
	target := "http://" + net.JoinHostPort(host, port) + "/readyz"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return errRuntimeConfig
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("healthcheck failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("healthcheck failed")
	}
	return nil
}
