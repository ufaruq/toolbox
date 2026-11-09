package main

import (
	"errors"
	"io"
	"os"

	"github.com/ufaruq/toolbox/internal/app"
	"github.com/ufaruq/toolbox/internal/githubruntime"
)

func newGitHubIntegration(cfg *githubConfig) (*app.GitHub, error) {
	if cfg == nil {
		return nil, nil
	}
	// Reject symlink and permissive key files before reading. Operator directories
	// must be private too; the runtime validates its disposable state directory.
	info, e := os.Lstat(cfg.keyFile)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16<<10 {
		return nil, errors.New("GitHub key must be a private regular file")
	}
	f, e := os.Open(cfg.keyFile)
	if e != nil {
		return nil, errors.New("GitHub key unavailable")
	}
	defer f.Close()
	current, e := f.Stat()
	if e != nil || !os.SameFile(info, current) {
		return nil, errors.New("GitHub key changed")
	}
	key, e := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if e != nil || len(key) > 16<<10 {
		return nil, errors.New("GitHub key unavailable")
	}
	defer clear(key)
	runtime, e := githubruntime.New(githubruntime.Config{AppID: cfg.appID, PrivateKey: key, OwnerID: cfg.ownerID, InstallationID: cfg.installationID, StateDirectory: cfg.stateDirectory})
	if e != nil {
		return nil, e
	}
	return &app.GitHub{Runtime: runtime}, nil
}
