package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ufaruq/toolbox/internal/backup"
	"github.com/ufaruq/toolbox/internal/runtimecfg"
	"github.com/ufaruq/toolbox/internal/security"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func backupCommand(command string) error {
	if command == "backup-decrypt" || command == "backup-verify" {
		if os.Getenv("TOOLBOX_RESTORE_ISOLATED") != "1" {
			return runtimecfg.ErrConfiguration
		}
		raw, err := runtimecfg.ReadSecret(os.Getenv("TOOLBOX_BACKUP_IDENTITY_FILE"))
		if err != nil {
			return err
		}
		path := os.Getenv("TOOLBOX_BACKUP_FILE")
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return backup.ErrBackup
		}
		f, err := os.Open(path)
		if err != nil {
			return backup.ErrBackup
		}
		defer f.Close()
		var out io.Writer = os.Stdout
		if command == "backup-verify" {
			out = io.Discard
		}
		return backup.Decrypt(f, out, strings.TrimSpace(string(raw)))
	}
	raw, err := os.ReadFile(os.Getenv("TOOLBOX_BACKUP_RECIPIENT_FILE"))
	if err != nil {
		return backup.ErrBackup
	}
	dir := os.Getenv("TOOLBOX_BACKUP_DIR")
	if dir == "" {
		return runtimecfg.ErrConfiguration
	}
	kind := "database"
	if command == "backup-static" {
		kind = "static-keys"
	}
	name := kind + "-" + time.Now().UTC().Format("20060102T150405Z") + "-" + security.ID() + ".age"
	f, err := os.OpenFile(filepath.Join(dir, name+".partial"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return backup.ErrBackup
	}
	defer f.Close()
	hash := sha256.New()
	out := io.MultiWriter(f, hash)
	var in io.Reader = os.Stdin
	if command == "backup-static" {
		reader, writer := io.Pipe()
		in = reader
		defer reader.Close()
		go func() {
			tw := tar.NewWriter(writer)
			dir := os.Getenv("TOOLBOX_STATIC_DIR")
			entries, e := os.ReadDir(dir)
			if e != nil {
				_ = writer.CloseWithError(backup.ErrBackup)
				return
			}
			for _, entry := range entries {
				if entry.Name() == "backup-identity" {
					continue
				}
				if !entry.Type().IsRegular() {
					_ = writer.CloseWithError(backup.ErrBackup)
					return
				}
				path := filepath.Join(dir, entry.Name())
				st, e := os.Lstat(path)
				if e != nil || !st.Mode().IsRegular() {
					_ = writer.CloseWithError(backup.ErrBackup)
					return
				}
				b, e := os.ReadFile(path)
				if e != nil {
					_ = writer.CloseWithError(backup.ErrBackup)
					return
				}
				e = tw.WriteHeader(&tar.Header{Name: entry.Name(), Mode: 0600, Size: int64(len(b)), ModTime: st.ModTime()})
				if e == nil {
					_, e = tw.Write(b)
				}
				clear(b)
				if e != nil {
					_ = writer.CloseWithError(backup.ErrBackup)
					return
				}
			}
			if tw.Close() != nil {
				_ = writer.CloseWithError(backup.ErrBackup)
				return
			}
			_ = writer.Close()
		}()
	}
	if err = backup.Encrypt(in, out, strings.TrimSpace(string(raw))); err != nil {
		return err
	}
	if f.Sync() != nil || f.Close() != nil {
		return backup.ErrBackup
	}
	if err = os.Rename(filepath.Join(dir, name+".partial"), filepath.Join(dir, name)); err != nil {
		return backup.ErrBackup
	}
	return output(map[string]any{"artifact": name, "kind": kind, "created_at": time.Now().UTC(), "ciphertext_sha256": hex.EncodeToString(hash.Sum(nil)), "image": os.Getenv("TOOLBOX_IMAGE_REF"), "key_provider": os.Getenv("TOOLBOX_KEY_PROVIDER"), "kms_key": os.Getenv("TOOLBOX_KMS_KEY")})
}

func backupLatest() error {
	b, err := os.ReadFile(filepath.Join(os.Getenv("TOOLBOX_BACKUP_DIR"), "latest-database.json"))
	if err != nil {
		return backup.ErrBackup
	}
	var m struct {
		Artifact string `json:"artifact"`
	}
	if json.Unmarshal(b, &m) != nil || !regexp.MustCompile(`^database-[A-Za-z0-9_-]+\.age$`).MatchString(m.Artifact) {
		return backup.ErrBackup
	}
	fmt.Println(m.Artifact)
	return nil
}
