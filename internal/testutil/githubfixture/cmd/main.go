// githubfixture serves the controlled HTTPS GitHub API used by Docker E2E tests.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ufaruq/toolbox/internal/testutil/githubfixture"
)

func main() {
	configPath := flag.String("config", "/run/config.json", "synthetic fixture configuration")
	certPath := flag.String("cert", "/run/server.crt", "TLS certificate")
	keyPath := flag.String("key", "/run/server.key", "TLS key")
	listen := flag.String("listen", ":9443", "HTTPS listen address")
	flag.Parse()
	configFile, err := os.Open(*configPath)
	if err != nil {
		log.Fatal("cannot open fixture configuration")
	}
	defer configFile.Close()
	var config githubfixture.Config
	decoder := json.NewDecoder(io.LimitReader(configFile, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		log.Fatal("cannot decode fixture configuration")
	}
	fixture, err := githubfixture.New(config)
	if err != nil {
		log.Fatal("invalid fixture configuration")
	}
	server := &http.Server{
		Addr: *listen, Handler: fixture,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
	}
	log.Print("controlled GitHub HTTPS fixture listening")
	if err := server.ListenAndServeTLS(*certPath, *keyPath); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
