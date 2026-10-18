package server

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed web/*
var web embed.FS

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && !(strings.HasPrefix(r.URL.Path, "/approve/") && len(strings.TrimPrefix(r.URL.Path, "/approve/")) == 36) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	name := "web/index.html"
	if s.OwnerOnly {
		name = "web/owner.html"
	}
	b, _ := web.ReadFile(name)
	_, _ = w.Write(b)
}
func (s *Server) appJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	name := "web/app.js"
	if s.OwnerOnly {
		name = "web/owner.js"
	}
	b, _ := web.ReadFile(name)
	_, _ = w.Write(b)
}
func (s *Server) appCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	b, _ := web.ReadFile("web/app.css")
	_, _ = w.Write(b)
}
