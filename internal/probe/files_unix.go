//go:build !windows

package probe

import (
	"fmt"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
	"os"
	"path/filepath"
	"syscall"
)

func nativeTemp(t model.Target) (string, func(), error) {
	base := ""
	if os.Geteuid() == 0 {
		// Ignore an inherited TMPDIR at the privileged boundary. /tmp is the
		// platform system temporary directory; sticky ownership protects the
		// root-owned child even when other users can create sibling entries.
		resolved, err := filepath.EvalSymlinks("/tmp")
		if err != nil {
			return "", func() {}, err
		}
		info, err := os.Lstat(resolved)
		if err != nil {
			return "", func() {}, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || st.Uid != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) || run.TrustedPath(filepath.Dir(resolved)) != nil {
			return "", func() {}, fmt.Errorf("safe temporary directory unavailable")
		}
		base = resolved
	}
	dir, err := os.MkdirTemp(base, "emudhraslop-native-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if nativeDropsIdentity(t) {
		// The less-privileged child must never be able to replace files that
		// the parent later opens with root privileges. Fixtures are public.
		err = os.Chmod(dir, 0755)
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
	}
	return dir, cleanup, nil
}
func nativeWrite(t model.Target, path string, data []byte) error {
	mode := os.FileMode(0600)
	if nativeDropsIdentity(t) {
		mode = 0644
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if err = file.Chmod(mode); err != nil {
		return err
	}
	_, err = file.Write(data)
	return err
}

func nativeDropsIdentity(t model.Target) bool {
	return os.Geteuid() == 0 && t.UID != nil && *t.UID != 0 && t.GID != nil
}

func nativeCache(t model.Target, dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if !nativeDropsIdentity(t) {
		return nil
	}
	file, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Chown(int(*t.UID), int(*t.GID))
}
