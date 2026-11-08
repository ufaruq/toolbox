// Package backup uses the standard age streaming format. Private recovery keys
// are needed only for restore, never for scheduled backup creation.
package backup

import (
	"errors"
	"filippo.io/age"
	"io"
)

var ErrBackup = errors.New("backup encryption or verification failed")

func Encrypt(in io.Reader, out io.Writer, recipient string) error {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return ErrBackup
	}
	w, err := age.Encrypt(out, r)
	if err != nil {
		return ErrBackup
	}
	if _, err = io.Copy(w, in); err != nil {
		return ErrBackup
	}
	if w.Close() != nil {
		return ErrBackup
	}
	return nil
}
func Decrypt(in io.Reader, out io.Writer, identity string) error {
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return ErrBackup
	}
	r, err := age.Decrypt(in, id)
	if err != nil {
		return ErrBackup
	}
	if _, err = io.Copy(out, r); err != nil {
		return ErrBackup
	}
	return nil
}
