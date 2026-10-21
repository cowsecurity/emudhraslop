package run

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/platform"
)

var ErrElevatedDenied = errors.New("elevated Windows probes are unsupported; use a non-elevated account")

// Windows ownership cannot be established from Unix mode bits. The product
// deliberately refuses elevated execution even when --allow-root-probes is set.
func TrustedPath(string) error { return ErrElevatedDenied }

func Elevated() (bool, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false, err
	}
	defer token.Close()
	var elevated, size uint32
	err = syscall.GetTokenInformation(token, 20, (*byte)(unsafe.Pointer(&elevated)), 4, &size)
	if err == nil && size != 4 {
		err = errors.New("invalid token elevation response")
	}
	return elevated != 0, err
}

func Exec(ctx context.Context, target model.Target, args []string, input []byte, environment map[string]string, opts Options) (Output, error) {
	var result Output
	if !platform.ValidPath(target.Executable) || !stringsExe(target.Executable) {
		return result, errors.New("absolute local .exe path required")
	}
	if opts.Timeout <= 0 || opts.MaxOutput <= 0 {
		return result, errors.New("invalid subprocess resource limits")
	}
	elevated, err := Elevated()
	if err != nil || elevated {
		return result, ErrElevatedDenied
	}
	if (target.UID != nil && *target.UID != uint32(os.Geteuid())) || (target.GID != nil && *target.GID != uint32(os.Getegid())) {
		return result, errors.New("Windows probes support only the current execution token")
	}
	// Reject device and remote targets before CreateProcess. Never invoke a
	// command shell, PATHEXT script, or a Windows Store execution alias.
	f, err := platform.OpenRead(target.Executable)
	if err != nil {
		return result, errors.New("local executable unavailable")
	}
	info, err := f.Stat()
	f.Close()
	if err != nil || !info.Mode().IsRegular() {
		return result, errors.New("regular executable required")
	}
	tmp, err := os.MkdirTemp("", "emudhraslop-probe-")
	if err != nil {
		return result, errors.New("cannot create isolated working directory")
	}
	defer os.RemoveAll(tmp)
	childCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(childCtx, target.Executable, args...)
	cmd.Dir = tmp
	// Windows requires SystemRoot to load standard OS libraries. Its canonical
	// value comes from GetWindowsDirectory, not a caller-controlled environment.
	windowsDir, err := systemWindowsDirectory()
	if err != nil {
		return result, errors.New("Windows system directory unavailable")
	}
	cmd.Env = []string{"SystemRoot=" + windowsDir, "PATH=" + filepath.Join(windowsDir, "System32"), "HOME=" + tmp, "USERPROFILE=" + tmp, "TEMP=" + tmp, "TMP=" + tmp}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seenKeys := map[string]bool{}
	for _, key := range keys {
		canonical := strings.ToUpper(key)
		if seenKeys[canonical] {
			return result, errors.New("case-duplicate Windows environment setting")
		}
		seenKeys[canonical] = true
		if err := validateEnvironment(key, environment[key]); err != nil {
			return result, err
		}
		cmd.Env = append(cmd.Env, key+"="+environment[key])
	}
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := &capped{limit: opts.MaxOutput}, &capped{limit: opts.MaxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	job, err := newJob()
	if err != nil {
		return result, errors.New("bounded process job unavailable")
	}
	defer syscall.CloseHandle(job)
	// No uncontained user code runs: the primary thread starts suspended and is
	// resumed only after assignment to the mandatory kill-on-close job.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x4, HideWindow: true}
	cmd.WaitDelay = time.Second
	cmd.Cancel = func() error { return terminateJob(job) }
	if err = cmd.Start(); err != nil {
		return result, err
	}
	if err = attachAndResume(job, uint32(cmd.Process.Pid)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return result, errors.New("process containment unavailable")
	}
	err = cmd.Wait()
	_ = terminateJob(job)
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
