//go:build !windows

package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

// TrustedPath rejects writable ancestors, including writable symlink targets.
func TrustedPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute executable path required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return errors.New("executable path cannot be resolved")
	}
	for _, current := range []string{filepath.Clean(path), resolved} {
		for {
			info, err := os.Stat(current)
			if err != nil {
				return errors.New("managed path cannot be inspected")
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
				return errors.New("root probe path is not root-owned and immutable to other users")
			}
			parent := filepath.Dir(current)
			if parent == current {
				break
			}
			current = parent
		}
	}
	return nil
}

func Exec(ctx context.Context, target model.Target, args []string, input []byte, environment map[string]string, opts Options) (Output, error) {
	var result Output
	if !filepath.IsAbs(target.Executable) {
		return result, errors.New("absolute executable path required")
	}
	if opts.Timeout <= 0 || opts.MaxOutput <= 0 {
		return result, errors.New("invalid subprocess resource limits")
	}
	childCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(childCtx, target.Executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if os.Geteuid() == 0 {
		if target.UID != nil && *target.UID != 0 {
			if target.GID == nil {
				return result, errors.New("non-root probes need an explicit gid")
			}
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: *target.UID, Gid: *target.GID, Groups: []uint32{}}
		} else {
			if !opts.AllowRoot {
				return result, ErrRootDenied
			}
			if err := TrustedPath(target.Executable); err != nil {
				return result, err
			}
			if target.GID != nil && *target.GID != uint32(os.Getegid()) {
				return result, errors.New("unsupported root execution group")
			}
		}
	} else if target.UID != nil && *target.UID != uint32(os.Geteuid()) {
		return result, errors.New("cannot probe another execution identity without privilege")
	} else if target.GID != nil && *target.GID != uint32(os.Getegid()) {
		return result, errors.New("cannot probe another execution group without privilege")
	}
	tempBase := ""
	if os.Geteuid() == 0 {
		// Do not let an inherited TMPDIR redirect root's HOME/working directory
		// into an untrusted account's mutable directory.
		tempBase = "/tmp"
		if !trustedTemporaryBase(tempBase) {
			return result, errors.New("safe temporary directory unavailable")
		}
	}
	tmp, err := os.MkdirTemp(tempBase, "emudhraslop-probe-")
	if err != nil {
		return result, errors.New("cannot create isolated working directory")
	}
	defer os.RemoveAll(tmp)
	if cmd.SysProcAttr.Credential != nil {
		if err := os.Chown(tmp, int(*target.UID), int(*target.GID)); err != nil {
			return result, errors.New("cannot prepare isolated execution identity")
		}
	}
	cmd.Dir = tmp
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + tmp}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validateEnvironment(key, environment[key]); err != nil {
			return result, err
		}
		cmd.Env = append(cmd.Env, key+"="+environment[key])
	}
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := &capped{limit: opts.MaxOutput}, &capped{limit: opts.MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	err = cmd.Run()
	result.Stdout, result.Stderr = stdout.buffer.Bytes(), stderr.buffer.Bytes()
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if stdout.exceeded || stderr.exceeded {
		return result, ErrOutputLimit
	}
	if childCtx.Err() != nil {
		return result, childCtx.Err()
	}
	return result, err
}

func trustedTemporaryBase(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for {
		info, err := os.Lstat(resolved)
		if err != nil || !info.IsDir() {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return false
		}
		parent := filepath.Dir(resolved)
		if parent == resolved {
			return true
		}
		resolved = parent
	}
}
