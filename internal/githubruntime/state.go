package githubruntime

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// validateStateDirectory rejects mutable ancestry before creating private state.
// A root-owned sticky temporary ancestor is safe: other users cannot rename our
// owned child. No symlinks or group/other-writable nonsticky ancestors are allowed.
func validateStateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return ErrDenied
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if os.IsNotExist(e) {
			if e = os.Mkdir(current, 0700); e != nil {
				return ErrDenied
			}
			info, e = os.Lstat(current)
		}
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrDenied
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return ErrDenied
		}
		uid := int(stat.Uid)
		if uid != 0 && uid != os.Geteuid() {
			return ErrDenied
		}
		if index == len(parts)-1 {
			if uid != os.Geteuid() || info.Mode().Perm() != 0700 {
				return ErrDenied
			}
		} else if info.Mode().Perm()&0022 != 0 && (uid != 0 || info.Mode()&os.ModeSticky == 0) {
			return ErrDenied
		}
	}
	return nil
}
