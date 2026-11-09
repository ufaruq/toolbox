package main

import (
	"testing"
)

func TestGitHubConfigExplicitBinding(t *testing.T) {
	base := map[string]string{"TOOLBOX_GITHUB_ENABLED": "true", "TOOLBOX_GITHUB_APP_ID": "5667548", "TOOLBOX_GITHUB_INSTALLATION_ID": "180004509", "TOOLBOX_GITHUB_OWNER_ID": "owner-id", "TOOLBOX_GITHUB_PRIVATE_KEY_FILE": "/private/operator/app.pem", "TOOLBOX_GITHUB_STATE_DIRECTORY": "/private/operator/gateway"}
	get := func(k string) string { return base[k] }
	if _, e := loadGitHubConfig(get, "workspace-local"); e != nil {
		t.Fatal(e)
	}
	for key := range base {
		saved := base[key]
		delete(base, key)
		if _, e := loadGitHubConfig(get, "workspace-local"); e == nil {
			t.Errorf("missing %s accepted", key)
		}
		base[key] = saved
	}
	for _, mode := range []string{"fixture", "oidc-local"} {
		if _, e := loadGitHubConfig(get, mode); e == nil {
			t.Errorf("real credentials accepted in %s", mode)
		}
	}
	for _, entry := range [][2]string{{"TOOLBOX_GITHUB_ENABLED", "false"}, {"TOOLBOX_GITHUB_APP_ID", "-1"}, {"TOOLBOX_GITHUB_INSTALLATION_ID", "01"}, {"TOOLBOX_GITHUB_OWNER_ID", " "}, {"TOOLBOX_GITHUB_PRIVATE_KEY_FILE", "relative.pem"}, {"TOOLBOX_GITHUB_STATE_DIRECTORY", "relative"}} {
		saved := base[entry[0]]
		base[entry[0]] = entry[1]
		if _, e := loadGitHubConfig(get, "workspace-local"); e == nil {
			t.Errorf("invalid %s accepted", entry[0])
		}
		base[entry[0]] = saved
	}
	if c, e := loadGitHubConfig(func(string) string { return "" }, "workspace-local"); e != nil || c != nil {
		t.Fatal("disabled configuration failed")
	}
}
