package main

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

type githubConfig struct {
	appID, ownerID, keyFile, stateDirectory string
	installationID                          int64
}

func loadGitHubConfig(getenv func(string) string, mode string) (*githubConfig, error) {
	keys := []string{"TOOLBOX_GITHUB_ENABLED", "TOOLBOX_GITHUB_APP_ID", "TOOLBOX_GITHUB_INSTALLATION_ID", "TOOLBOX_GITHUB_OWNER_ID", "TOOLBOX_GITHUB_PRIVATE_KEY_FILE", "TOOLBOX_GITHUB_STATE_DIRECTORY"}
	configured := false
	for _, key := range keys {
		configured = configured || getenv(key) != ""
	}
	if !configured {
		return nil, nil
	}
	invalid := errors.New("GitHub requires explicit workspace-local operator binding and private absolute paths")
	if mode != "workspace-local" || getenv(keys[0]) != "true" {
		return nil, invalid
	}
	for _, key := range keys {
		v := getenv(key)
		if v == "" || v != strings.TrimSpace(v) || strings.ContainsAny(v, "\x00\r\n") || len(v) > 4096 {
			return nil, invalid
		}
	}
	appID, err := strconv.ParseInt(getenv(keys[1]), 10, 64)
	if err != nil || appID <= 0 || strconv.FormatInt(appID, 10) != getenv(keys[1]) {
		return nil, invalid
	}
	install, err := strconv.ParseInt(getenv(keys[2]), 10, 64)
	if err != nil || install <= 0 || strconv.FormatInt(install, 10) != getenv(keys[2]) {
		return nil, invalid
	}
	c := &githubConfig{appID: getenv(keys[1]), installationID: install, ownerID: getenv(keys[3]), keyFile: getenv(keys[4]), stateDirectory: getenv(keys[5])}
	if len(c.ownerID) > 128 || !filepath.IsAbs(c.keyFile) || !filepath.IsAbs(c.stateDirectory) || filepath.Clean(c.keyFile) != c.keyFile || filepath.Clean(c.stateDirectory) != c.stateDirectory {
		return nil, invalid
	}
	return c, nil
}
