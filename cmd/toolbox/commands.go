package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/bootstrap"
	"github.com/ufaruq/toolbox/internal/connectors/gdrive"
	"github.com/ufaruq/toolbox/internal/monitor"
	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/recovery"
	"github.com/ufaruq/toolbox/internal/runtimecfg"
	"github.com/ufaruq/toolbox/internal/secretstore"
	"github.com/ufaruq/toolbox/internal/security"
	"github.com/ufaruq/toolbox/internal/server"
	"github.com/ufaruq/toolbox/internal/store"
	"github.com/ufaruq/toolbox/internal/strict"
	"github.com/ufaruq/toolbox/internal/tokens"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var errProductionGate = errors.New("production owner authentication and live Google validation are not implemented release gates")

func output(v any) error { return json.NewEncoder(os.Stdout).Encode(v) }
func run() error {
	command := "fixture"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if len(os.Args) > 2 {
		return runtimecfg.ErrConfiguration
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "init" {
		dir := os.Getenv("TOOLBOX_INIT_DIR")
		if dir == "" {
			return runtimecfg.ErrConfiguration
		}
		return bootstrap.Init(dir)
	}
	if command == "init-monitor" {
		return bootstrap.InitMonitor(os.Getenv("TOOLBOX_INIT_DIR"))
	}
	if command == "monitor" {
		dsn, err := databaseFile()
		if err != nil {
			return err
		}
		repo, err := store.OpenPostgres(ctx, dsn)
		if err != nil {
			return err
		}
		defer repo.Close()
		r, err := monitor.Inspect(ctx, repo, os.Getenv("TOOLBOX_BACKUP_DIR"), os.Getenv("TOOLBOX_JOB_STATUS_DIR"))
		if err != nil {
			return err
		}
		_ = output(r)
		if !r.Healthy {
			return errors.New("monitoring thresholds exceeded")
		}
		return nil
	}
	if command == "init-backups" {
		return bootstrap.InitBackups(os.Getenv("TOOLBOX_INIT_DIR"))
	}
	if command == "backup-latest" {
		return backupLatest()
	}
	if command == "backup-encrypt" || command == "backup-static" || command == "backup-decrypt" || command == "backup-verify" {
		return backupCommand(command)
	}
	if command == "recover-invalidate" {
		if os.Getenv("TOOLBOX_RESTORE_ISOLATED") != "1" {
			return runtimecfg.ErrConfiguration
		}
		dsn, err := databaseFile()
		if err != nil {
			return err
		}
		repo, err := store.OpenPostgres(ctx, dsn)
		if err != nil {
			return err
		}
		defer repo.Close()
		r, err := recovery.Invalidate(ctx, repo)
		if err != nil {
			return err
		}
		return output(r)
	}
	if command == "provision" {
		return bootstrap.Provision(ctx, os.Getenv("TOOLBOX_INIT_DIR"))
	}
	if command == "migrate" {
		return migrate(ctx)
	}
	if command == "serve" {
		fmt.Fprintln(os.Stderr, "Production serve is blocked: owner OIDC and live Google validation are unfinished.")
		return errProductionGate
	}
	if command == "fixture" && os.Getenv("TOOLBOX_DATABASE_FILE") == "" {
		return runLegacy()
	}
	cfg, err := runtimecfg.Load(os.Getenv)
	if err != nil {
		return err
	}
	if command == "healthcheck" {
		client := http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, e := client.Get(cfg.Origin + "/readyz")
		if e != nil {
			return secretstore.ErrUnavailable
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return secretstore.ErrUnavailable
		}
		return nil
	}
	repo, secrets, close, err := openRuntime(ctx, cfg)
	if err != nil {
		return err
	}
	defer close()
	switch command {
	case "preflight", "preflight-storage":
		if err = secrets.CheckWrapper(ctx); err != nil {
			return err
		}
		_ = output(map[string]any{"storage": "ready", "key_provider": cfg.KeyProvider, "production_authentication": "blocked"})
		if cfg.Mode == "production" && command == "preflight" {
			return errProductionGate
		}
		return nil
	case "retention":
		r, e := secrets.RunRetention(ctx, repo, secretstore.RetentionPolicy{})
		if e != nil {
			return e
		}
		return output(r)
	case "fixture", "cleanup":
		if cfg.Mode != "fixture" {
			return errProductionGate
		}
		provider, e := oauth.NewFixtureProvider("fixture-client", cfg.Origin+"/oauth/callback")
		if e != nil {
			return e
		}
		flow, e := oauth.NewService(repo, secrets, provider)
		if e != nil {
			return e
		}
		integration := &app.Integration{OAuth: flow, TokenManager: &tokens.Manager{Repository: repo, Secrets: secrets, Provider: provider}, Drive: gdrive.NewFixture(&app.FixtureDrive{}), Fixture: provider}
		if command == "cleanup" {
			r, e := server.RunCleanup(ctx, repo, integration)
			if e != nil {
				return e
			}
			_ = output(r)
			if r.Failed > 0 {
				return secretstore.ErrUnavailable
			}
			return nil
		}
		return serveFixture(ctx, cfg, repo, secrets, integration)
	default:
		return runtimecfg.ErrConfiguration
	}
}
func databaseFile() (string, error) {
	b, e := runtimecfg.ReadSecret(os.Getenv("TOOLBOX_DATABASE_FILE"))
	if e != nil {
		return "", e
	}
	dsn := strings.TrimSpace(string(b))
	if e = runtimecfg.ValidateDSN(dsn); e != nil {
		return "", e
	}
	return dsn, nil
}
func migrate(ctx context.Context) error {
	dsn, err := databaseFile()
	if err != nil {
		return err
	}
	repo, err := store.OpenPostgres(ctx, dsn)
	if err != nil {
		return err
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return secretstore.ErrUnavailable
	}
	defer pool.Close()
	if err = secretstore.Migrate(ctx, pool, "toolbox_credentials"); err != nil {
		return err
	}
	return repo.ConfigureRoles(ctx, "toolbox", "toolbox_credentials", store.Roles{API: "toolbox_api", Cleanup: "toolbox_cleanup", Retention: "toolbox_retention", Monitor: "toolbox_monitor"})
}
func openRuntime(ctx context.Context, c runtimecfg.Config) (*store.Postgres, *secretstore.Postgres, func(), error) {
	noop := func() {}
	if !c.Persistent {
		return nil, nil, noop, runtimecfg.ErrConfiguration
	}
	repo, err := store.OpenPostgres(ctx, c.DSN)
	if err != nil {
		return nil, nil, noop, err
	}
	if err = repo.RuntimeSafe(ctx); err != nil {
		repo.Close()
		return nil, nil, noop, err
	}
	if err = repo.CheckMigrations(ctx); err != nil {
		repo.Close()
		return nil, nil, noop, err
	}
	pool, err := pgxpool.New(ctx, c.DSN)
	if err != nil {
		repo.Close()
		return nil, nil, noop, secretstore.ErrUnavailable
	}
	closeKMS := func() error { return nil }
	close := func() { _ = closeKMS(); pool.Close(); repo.Close() }
	var wrapper secretstore.KeyWrapper
	if c.KeyProvider == "local" {
		b, e := runtimecfg.ReadSecret(c.KeyFile)
		if e != nil {
			close()
			return nil, nil, noop, e
		}
		key, e := hex.DecodeString(strings.TrimSpace(string(b)))
		if e != nil {
			close()
			return nil, nil, noop, runtimecfg.ErrConfiguration
		}
		wrapper, err = secretstore.NewLocalWrapper(key)
		clear(key)
	} else {
		wrapper, closeKMS, err = secretstore.NewGCPWrapper(ctx, c.KMSKey)
		if err != nil {
			closeKMS = func() error { return nil }
		}
	}
	if err != nil {
		close()
		return nil, nil, noop, err
	}
	envelope, err := secretstore.NewEnvelope(wrapper, c.Deployment, c.SecretSchema)
	if err != nil {
		close()
		return nil, nil, noop, err
	}
	secrets, err := secretstore.NewPostgres(ctx, secretstore.PostgresConfig{Pool: pool, Schema: c.SecretSchema, Envelope: envelope})
	if err != nil {
		close()
		return nil, nil, noop, err
	}
	return repo, secrets, close, nil
}
func serveFixture(ctx context.Context, c runtimecfg.Config, repo *store.Postgres, secrets *secretstore.Postgres, integration *app.Integration) error {
	var ring security.SigningKeyRing
	var peppers security.PepperConfig
	for _, file := range []struct {
		path string
		out  any
	}{{c.SigningFile, &ring}, {c.PepperFile, &peppers}} {
		b, e := runtimecfg.ReadSecret(file.path)
		if e != nil {
			return e
		}
		if strict.Decode(b, file.out) != nil {
			return runtimecfg.ErrConfiguration
		}
	}
	signer, e := security.NewKeyRingSigner(c.Origin, ring)
	if e != nil {
		return e
	}
	pepper, e := security.NewPepperRing(peppers)
	if e != nil {
		return e
	}
	if e = secrets.CheckWrapper(ctx); e != nil {
		return e
	}
	api, e := server.New(server.Config{Repository: repo, Signer: signer, PepperKeys: pepper, Origin: c.Origin, Fixture: true, Readiness: func(ctx context.Context) error {
		if e := repo.Ping(ctx); e != nil {
			return e
		}
		return secrets.CheckWrapper(ctx)
	}}, integration)
	if e != nil {
		return e
	}
	srv := &http.Server{Addr: c.Addr, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 25 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	go func() {
		timer := time.NewTicker(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				jobCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
				r, err := api.RunCleanup(jobCtx)
				cancel()
				if err != nil || r.Processed > 0 {
					_ = output(map[string]any{"job": "cleanup", "report": r, "failed": err != nil})
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case e := <-done:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
}
