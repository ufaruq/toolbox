// Package keycloaktest contains isolated, synthetic infrastructure for the real
// Keycloak broker acceptance test. Production packages must not import it.
package keycloaktest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Endpoints are reachable both from the test process and dedicated containers.
type Endpoints struct{ Broker, RealmIssuer, OktaIssuer, GoogleIssuer string }

// Credentials are freshly generated for each run and must never be logged.
type Credentials struct{ Owner, Okta, Google, Operator string }

// Harness owns only the Docker resources created by its Start call.
type Harness struct {
	Endpoints
	Credentials Credentials
	Client      *http.Client
}

// Start imports a private test realm into a real pinned Keycloak on a dedicated
// Docker bridge. Only controlled local HTTPS services use the generated CA.
// Docker access must be explicitly authorized by the outer test invocation.
func Start(t testing.TB, realm string, render func(Endpoints, Credentials) ([]byte, error)) *Harness {
	t.Helper()
	brokerImage := os.Getenv("TOOLBOX_TEST_KEYCLOAK_IMAGE")
	if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(brokerImage) {
		t.Fatal("TOOLBOX_TEST_KEYCLOAK_IMAGE must be the immutable local image ID from scripts/build-vendor-image keycloak; use make keycloak-check or make test-all")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	dir := t.TempDir()
	name := "toolbox-keycloak-" + random(t)
	subnetID, _ := strconv.ParseUint(random(t)[:2], 16, 8)
	network := docker(t, ctx, "network", "create", "--subnet", fmt.Sprintf("10.253.%d.0/24", subnetID), "--label", "toolbox.test=keycloak", name)
	t.Cleanup(func() { cleanup(t, "network", "rm", network) })
	var networks []struct {
		IPAM struct {
			Config []struct{ Subnet, Gateway string }
		}
	}
	if err := json.Unmarshal([]byte(docker(t, ctx, "network", "inspect", network)), &networks); err != nil || len(networks) != 1 || len(networks[0].IPAM.Config) != 1 {
		t.Fatal("inspect dedicated Keycloak test bridge")
	}
	_, subnet, err := net.ParseCIDR(networks[0].IPAM.Config[0].Subnet)
	if err != nil || subnet.IP.To4() == nil {
		t.Fatal("Keycloak test bridge requires IPv4")
	}
	upstreamIP, brokerIP := append(net.IP(nil), subnet.IP.To4()...), append(net.IP(nil), subnet.IP.To4()...)
	upstreamIP[3] += 10
	brokerIP[3] += 11
	h := &Harness{Endpoints: Endpoints{Broker: "https://" + brokerIP.String() + ":8443", OktaIssuer: "https://" + upstreamIP.String() + ":9443/okta", GoogleIssuer: "https://" + upstreamIP.String() + ":9443/google"}, Credentials: Credentials{Owner: random(t), Okta: random(t), Google: random(t), Operator: random(t)}}
	h.RealmIssuer = h.Broker + "/realms/" + realm
	ca, cert, key := certificates(t, []net.IP{upstreamIP, brokerIP})
	write(t, filepath.Join(dir, "ca.pem"), ca)
	write(t, filepath.Join(dir, "server.pem"), cert)
	write(t, filepath.Join(dir, "server.key"), key)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	// These IPs are exclusively the bridge we just created. No Internet traffic
	// uses this transport or bypasses the managed environment's egress proxy.
	h.Client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, Timeout: 15 * time.Second}
	t.Cleanup(h.Client.CloseIdleConnections)
	config, _ := json.Marshal(Config{OktaIssuer: h.OktaIssuer, GoogleIssuer: h.GoogleIssuer, OktaClientID: "upstream-okta", OktaClientSecret: h.Credentials.Okta, GoogleClientID: "upstream-google", GoogleClientSecret: h.Credentials.Google})
	write(t, filepath.Join(dir, "fixture.json"), config)
	realmJSON, err := render(h.Endpoints, h.Credentials)
	if err != nil {
		t.Fatal("render private Keycloak test realm")
	}
	write(t, filepath.Join(dir, "realm.json"), realmJSON)
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "../../.."))
	buildDir := filepath.Join(dir, "build")
	if err := os.Mkdir(buildDir, 0700); err != nil {
		t.Fatal("create isolated fixture build context")
	}
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(buildDir, "upstream"), "./internal/testutil/keycloaktest/cmd")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic OIDC upstream: %s", output)
	}
	write(t, filepath.Join(buildDir, "Dockerfile"), []byte("FROM scratch\nCOPY upstream /upstream\nUSER 1000:1000\nENTRYPOINT [\"/upstream\"]\n"))
	image := name + ":fixture"
	docker(t, ctx, "build", "--network=none", "--tag", image, "--file", filepath.Join(buildDir, "Dockerfile"), buildDir)
	t.Cleanup(func() { cleanup(t, "image", "rm", image) })
	uid := strconv.Itoa(os.Getuid())
	fixture := docker(t, ctx, "run", "--detach", "--name", name+"-upstream", "--network", network, "--ip", upstreamIP.String(), "--user", uid+":"+uid,
		"--mount", mount(dir, "fixture.json", "/run/config.json"), "--mount", mount(dir, "server.pem", "/run/server.pem"), "--mount", mount(dir, "server.key", "/run/server.key"),
		image, "--config", "/run/config.json", "--cert", "/run/server.pem", "--key", "/run/server.key", "--listen", ":9443")
	t.Cleanup(func() { cleanup(t, "rm", "--force", fixture) })
	waitReady(t, ctx, h.Client, "https://"+upstreamIP.String()+":9443/healthz", "controlled OIDC upstream", fixture)
	// The outer runner builds the reviewed recipe and supplies its immutable ID.
	docker(t, ctx, "image", "inspect", brokerImage)
	broker := docker(t, ctx, "run", "--detach", "--name", name+"-broker", "--network", network, "--ip", brokerIP.String(), "--user", uid+":0",
		"--env", "NO_PROXY="+strings.Trim(os.Getenv("NO_PROXY")+","+upstreamIP.String()+","+brokerIP.String(), ","),
		"--env", "no_proxy="+strings.Trim(os.Getenv("no_proxy")+","+upstreamIP.String()+","+brokerIP.String(), ","),
		"--mount", mount(dir, "realm.json", "/opt/keycloak/data/import/realm.json"), "--mount", mount(dir, "ca.pem", "/opt/keycloak/conf/truststores/test-ca.pem"),
		"--mount", mount(dir, "server.pem", "/opt/keycloak/conf/server.pem"), "--mount", mount(dir, "server.key", "/opt/keycloak/conf/server.key"),
		brokerImage, "start-dev", "--import-realm", "--hostname="+h.Broker, "--http-enabled=false", "--https-certificate-file=/opt/keycloak/conf/server.pem", "--https-certificate-key-file=/opt/keycloak/conf/server.key", "--log-level=warn")
	t.Cleanup(func() { cleanup(t, "rm", "--force", broker) })
	t.Cleanup(func() {
		if t.Failed() {
			logCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			output, _ := command(logCtx, "logs", "--tail", "100", broker).CombinedOutput()
			for _, line := range strings.Split(string(output), "\n") {
				if strings.Contains(line, "ERROR") || strings.Contains(line, "Exception") || strings.Contains(line, "error=") {
					for _, secret := range []string{h.Credentials.Owner, h.Credentials.Okta, h.Credentials.Google, h.Credentials.Operator} {
						line = strings.ReplaceAll(line, secret, "[redacted]")
					}
					line = regexp.MustCompile(`https?://[^\s]+`).ReplaceAllString(line, "[local URL redacted]")
					line = regexp.MustCompile(`code_id="[^"]*"`).ReplaceAllString(line, `code_id="[redacted]"`)
					t.Log(line)
				}
			}
		}
	})
	waitReady(t, ctx, h.Client, h.RealmIssuer+"/.well-known/openid-configuration", "pinned Keycloak broker", broker)
	t.Log("real Keycloak ready: " + brokerImage)
	return h
}

func waitReady(t testing.TB, ctx context.Context, client *http.Client, target, stage, container string) {
	t.Helper()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	attempt := 0
	for {
		response, err := client.Get(target)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				return
			}
		}
		attempt++
		if attempt%5 == 0 && docker(t, ctx, "inspect", "--format", "{{.State.Running}}", container) != "true" {
			t.Fatalf("%s container exited before becoming ready", stage)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", stage)
		case <-ticker.C:
		}
	}
}

func docker(t testing.TB, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := command(ctx, args...).CombinedOutput()
	if err != nil {
		// Never include arguments, logs or provider responses; they may contain
		// the generated realm's private credentials.
		t.Fatalf("local Docker %s failed (%T): %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output))
}

func cleanup(t testing.TB, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := command(ctx, args...).Run(); err != nil {
		t.Errorf("clean up owned Keycloak Docker %s resource", args[0])
	}
}

func command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "docker", append([]string{"--host=unix:///var/run/docker.sock"}, args...)...)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if name != "DOCKER_HOST" && name != "DOCKER_CONTEXT" && name != "DOCKER_TLS" && name != "DOCKER_TLS_VERIFY" && name != "DOCKER_CERT_PATH" {
			cmd.Env = append(cmd.Env, item)
		}
	}
	return cmd
}

func mount(dir, file, target string) string {
	return "type=bind,src=" + filepath.Join(dir, file) + ",dst=" + target + ",readonly"
}

func random(t testing.TB) string {
	t.Helper()
	var data [24]byte
	if _, err := rand.Read(data[:]); err != nil {
		t.Fatal("generate private test credential")
	}
	return hex.EncodeToString(data[:])
}

func write(t testing.TB, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal("write private Keycloak test asset")
	}
}

func certificates(t testing.TB, ips []net.IP) (ca, certificate, privateKey []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate test CA")
	}
	now := time.Now()
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Toolbox isolated Keycloak acceptance CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal("sign test CA")
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate test service key")
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: ips, Subject: pkix.Name{CommonName: "isolated Keycloak acceptance services"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &serverKey.PublicKey, key)
	if err != nil {
		t.Fatal("sign test service certificate")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(fmt.Errorf("encode test service key: %w", err))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
