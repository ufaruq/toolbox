// Package bootstrap creates deployment files once. It never repairs missing key
// material by generating replacements: that would make stored ciphertext unusable.
package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/ufaruq/toolbox/internal/runtimecfg"
	"github.com/ufaruq/toolbox/internal/security"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var ErrBootstrap = errors.New("bootstrap incomplete; preserve existing files and follow recovery documentation")
var privateFiles = []string{"signing.json", "peppers.json", "local-root", "deployment-id", "api.dsn", "cleanup.dsn", "retention.dsn", "migration.dsn", "admin.dsn", "roles.json", "postgres-password", "ca.key", "postgres.key"}

func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b)
}
func Init(dir string) error {
	if st, err := os.Lstat(dir); err == nil {
		if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return ErrBootstrap
		}
		if _, err = os.Stat(filepath.Join(dir, "complete")); err == nil {
			for _, f := range privateFiles {
				if _, err := runtimecfg.ReadSecret(filepath.Join(dir, f)); err != nil {
					return ErrBootstrap
				}
			}
			return nil
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) > 0 {
			return ErrBootstrap
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrBootstrap
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ErrBootstrap
	}
	write := func(name string, data []byte, mode os.FileMode) error {
		f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			return ErrBootstrap
		}
		_, e = f.Write(data)
		sync := f.Sync()
		close := f.Close()
		if e != nil || sync != nil || close != nil {
			return ErrBootstrap
		}
		return nil
	}
	jsonWrite := func(name string, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		return write(name, b, 0600)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ErrBootstrap
	}
	if err = jsonWrite("signing.json", security.SigningKeyRing{Active: "initial", PrivateKey: base64.StdEncoding.EncodeToString(priv), PublicKeys: map[string]string{"initial": base64.StdEncoding.EncodeToString(pub)}}); err != nil {
		return err
	}
	pepper := make([]byte, 32)
	_, err = rand.Read(pepper)
	if err != nil {
		return ErrBootstrap
	}
	if err = jsonWrite("peppers.json", security.PepperConfig{Active: "initial", Keys: map[string]string{"initial": base64.StdEncoding.EncodeToString(pepper)}}); err != nil {
		return err
	}
	for _, f := range []string{"local-root", "deployment-id"} {
		if err = write(f, []byte(random()), 0600); err != nil {
			return err
		}
	}
	roles := map[string]string{}
	for _, role := range []string{"postgres", "toolbox_migrate", "toolbox_api", "toolbox_cleanup", "toolbox_retention"} {
		roles[role] = random()
	}
	if err = jsonWrite("roles.json", roles); err != nil {
		return err
	}
	if err = write("postgres-password", []byte(roles["postgres"]), 0600); err != nil {
		return err
	}
	for filename, role := range map[string]string{"admin.dsn": "postgres", "migration.dsn": "toolbox_migrate", "api.dsn": "toolbox_api", "cleanup.dsn": "toolbox_cleanup", "retention.dsn": "toolbox_retention"} {
		u := &url.URL{Scheme: "postgres", Host: "postgres:5432", Path: "/toolbox", User: url.UserPassword(role, roles[role])}
		q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {"/run/toolbox/ca.crt"}, "search_path": {"toolbox,pg_catalog"}}
		u.RawQuery = q.Encode()
		if err = write(filename, []byte(u.String()), 0600); err != nil {
			return err
		}
	}
	now := time.Now()
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			panic("random unavailable")
		}
		return n
	}
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ErrBootstrap
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Toolbox deployment CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		return ErrBootstrap
	}
	serverPub, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ErrBootstrap
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "postgres"}, DNSNames: []string{"postgres", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, cert, ca, serverPub, caKey)
	if err != nil {
		return ErrBootstrap
	}
	for name, key := range map[string]ed25519.PrivateKey{"ca.key": caKey, "postgres.key": serverKey} {
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return ErrBootstrap
		}
		if err = write(name, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
			return err
		}
	}
	for name, der := range map[string][]byte{"ca.crt": caDER, "postgres.crt": serverDER} {
		if err = write(name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
			return err
		}
	}
	return write("complete", []byte("v1\n"), 0600)
}
