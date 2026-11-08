// Command keycloaktest runs synthetic OIDC providers for real Keycloak tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ufaruq/toolbox/internal/testutil/keycloaktest"
)

func main() {
	configPath := flag.String("config", "", "private synthetic configuration file")
	certPath := flag.String("cert", "", "TLS certificate file")
	keyPath := flag.String("key", "", "TLS private key file")
	listen := flag.String("listen", ":8443", "TLS listen address")
	flag.Parse()
	if *configPath == "" || *certPath == "" || *keyPath == "" {
		fail("missing fixture arguments")
	}
	file, err := os.Open(*configPath)
	if err != nil {
		fail("read fixture configuration")
	}
	var config keycloaktest.Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&config)
	_ = file.Close()
	if err != nil {
		fail("decode fixture configuration")
	}
	handler, err := keycloaktest.New(config)
	if err != nil {
		fail("configure synthetic providers")
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second}
	if err := server.ListenAndServeTLS(*certPath, *keyPath); err != nil {
		fail("synthetic provider server stopped")
	}
}

func fail(stage string) {
	_, _ = fmt.Fprintln(os.Stderr, stage)
	os.Exit(1)
}
