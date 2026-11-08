package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ufaruq/toolbox/internal/oauth"
	"github.com/ufaruq/toolbox/internal/security"
)

type pkceProbe interface {
	Begin() (string, error)
	Complete(context.Context, string, string) (oauth.ProbeStatus, error)
	Status() oauth.ProbeStatus
}

const probeScript = `document.getElementById('start-form')?.addEventListener('submit',async event=>{
 event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;
 try{const response=await fetch('/probe/start',{method:'POST',credentials:'same-origin',cache:'no-store'});
 if(!response.ok)throw Error('Could not start the check. Stop and restart this tool.');
 const value=await response.json();location.assign(value.authorization_url);
 }catch(error){document.getElementById('status').textContent=error.message;button.disabled=false;}
});`

var probePage = template.Must(template.New("probe").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Toolbox Google client check</title><script src="/probe.js" defer></script><h1>Verify your Google OAuth client</h1><p>This uses four separate consent flows: matching verifier, missing verifier, incorrect verifier, then matching verifier again.</p><p>Use your dedicated test client. This check revokes its Google app authorization when finished. It does not create a Toolbox connection or enable the runtime.</p><p>Completed: {{.Completed}} / 4</p>{{if .Done}}<p>PASS. Both negative exchanges were rejected and the final positive exchange passed. Probe tokens were revoked. Stop this tool, then set TOOLBOX_GOOGLE_PKCE_VALIDATED=true for this exact client configuration.</p>{{else if .Failed}}<p>FAILED. Keep TOOLBOX_GOOGLE_PKCE_VALIDATED=false. Stop the tool and inspect its configuration. If cleanup or the process was interrupted, remove this test app’s access in your Google Account before retrying.</p>{{else}}<form id="start-form" method="post" action="/probe/start"><button type="submit">Continue with Google</button></form><p id="status" role="status"></p>{{end}}</html>`))

func newProbeHandler(origin string, p pkceProbe) http.Handler {
	u, _ := url.Parse(origin)
	var mu sync.Mutex
	binding := ""
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.Host != u.Host || r.Header.Get("X-HTTP-Method-Override") != "" {
			http.Error(w, "Invalid request", 400)
			return
		}
		if r.URL.Path != "/oauth/callback" && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
			http.Error(w, "Invalid query", 400)
			return
		}
		cookie, _ := r.Cookie("toolbox_google_probe")
		switch {
		case r.Method == "GET" && r.URL.Path == "/probe.js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			_, _ = w.Write([]byte(probeScript))
		case r.Method == "GET" && r.URL.Path == "/":
			// The start form requires an Origin header. no-referrer can suppress
			// it in Chromium; same-origin preserves it without sending it to Google.
			w.Header().Set("Referrer-Policy", "same-origin")
			if cookie == nil || len(cookie.Value) != 43 {
				http.SetCookie(w, &http.Cookie{Name: "toolbox_google_probe", Value: security.Random(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 1800})
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = probePage.Execute(w, p.Status())
		case r.Method == "POST" && r.URL.Path == "/probe/start":
			if cookie == nil || len(cookie.Value) != 43 || r.Header.Get("Origin") != origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "Not authorized", 403)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			authorization, err := p.Begin()
			if err != nil {
				http.Error(w, "Probe unavailable. Stop and restart the check.", 409)
				return
			}
			binding = security.Hash(cookie.Value)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"authorization_url": authorization})
		case r.Method == "GET" && r.URL.Path == "/oauth/callback":
			mu.Lock()
			defer mu.Unlock()
			if cookie == nil || !security.Equal(binding, security.Hash(cookie.Value)) {
				http.Error(w, "Not authorized", 403)
				return
			}
			q, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil || len(r.URL.RawQuery) > 12288 || len(q) > 20 || q.Get("state") == "" || q.Get("code") == "" || q.Has("error") || q.Get("iss") != "" && q.Get("iss") != "https://accounts.google.com" {
				http.Error(w, "Invalid callback. Restart the check after cancelled consent.", 400)
				return
			}
			for k, v := range q {
				if len(k) > 128 || len(v) != 1 || len(v[0]) > 4096 || strings.ContainsAny(k+v[0], "\x00\r\n") {
					http.Error(w, "Invalid callback", 400)
					return
				}
			}
			status, err := p.Complete(r.Context(), q.Get("state"), q.Get("code"))
			if err != nil {
				log.Print("Google client probe step failed; runtime gate remains disabled.")
			} else {
				log.Printf("Google client probe: %d of 4 steps passed; complete=%t", status.Completed, status.Done)
			}
			binding = ""
			http.Redirect(w, r, "/", http.StatusSeeOther)
		default:
			http.NotFound(w, r)
		}
	})
}

func runGooglePKCECheck() error {
	cfg, err := loadConfig(func(k string) string {
		if k == "TOOLBOX_MODE" {
			return "fixture"
		}
		return os.Getenv(k)
	})
	if err != nil || os.Getenv("TOOLBOX_ORIGIN") != cfg.origin {
		return errors.New("probe requires exact loopback origin")
	}
	for _, key := range []string{"TOOLBOX_GOOGLE_CLIENT_ID", "TOOLBOX_GOOGLE_CLIENT_SECRET"} {
		v := os.Getenv(key)
		if v == "" || v == "REPLACE_LOCALLY" || len(v) > 4096 || v != strings.TrimSpace(v) || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("probe requires Google test client configuration")
		}
	}
	p, err := oauth.NewPKCEProbe(oauth.GoogleConfig{ClientID: os.Getenv("TOOLBOX_GOOGLE_CLIENT_ID"), ClientSecret: os.Getenv("TOOLBOX_GOOGLE_CLIENT_SECRET"), CallbackURL: cfg.origin + "/oauth/callback", AllowLoopbackHTTP: true})
	if err != nil {
		return err
	}
	defer func() {
		if p.Close(context.Background()) != nil {
			log.Print("Probe cleanup incomplete. Remove the test app authorization in your Google Account.")
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: cfg.addr, Handler: newProbeHandler(cfg.origin, p), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	fmt.Printf("Google client verification: open %s/ in your browser. Runtime gate stays disabled until all four checks pass.\n", cfg.origin)
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}
	stop, finish := context.WithTimeout(context.Background(), 5*time.Second)
	defer finish()
	return server.Shutdown(stop)
}
