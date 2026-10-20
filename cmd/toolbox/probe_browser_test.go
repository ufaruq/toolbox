package main

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestProbeBrowserFlow(t *testing.T) {
	if os.Getenv("TOOLBOX_TEST_WORKSPACE_BROWSER") != "1" {
		t.Skip("requires pinned Playwright and Chromium")
	}
	ts := httptest.NewUnstartedServer(nil)
	defer ts.Close()
	origin := "http://" + ts.Listener.Addr().String()
	probe := &syntheticProbe{}
	ts.Config.Handler = newProbeHandler(origin, probe)
	ts.Start()
	_, source, _, _ := runtime.Caller(0)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", filepath.Join(filepath.Dir(source), "../../tests/browser/probe_e2e.py"), origin)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic probe navigation failed: %s", out)
	}
}
