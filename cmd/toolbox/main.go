// Toolbox's executable is deliberately fixture-only until a production owner IdP
// and live Google integration gates have been selected and reviewed.
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
	"github.com/ufaruq/toolbox/internal/oauth"
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
	if os.Getenv("TOOLBOX_MODE") != "fixture" {
		return errors.New("only explicitly selected fixture mode is supported")
	}
	addr := os.Getenv("TOOLBOX_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	host, _, e := net.SplitHostPort(addr)
	if e != nil || !(host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return errors.New("fixture server must bind loopback")
	}
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
