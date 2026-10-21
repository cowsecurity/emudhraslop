package run

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func TestWindowsProbeChild(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "env-child":
		fmt.Printf("%s|%s|%s", os.Getenv("EMUDHRASLOP_TEST_SECRET"), os.Getenv("NODE_OPTIONS"), os.Getenv("SSL_CERT_FILE"))
		os.Exit(0)
	case "flood-child":
		for {
			fmt.Print(strings.Repeat("x", 1024))
		}
	case "linger-child":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "tree-child":
		exe, _ := os.Executable()
		child := exec.Command(exe, "-test.run=TestWindowsProbeChild", "--", "linger-child")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(23)
		}
		fmt.Println(child.Process.Pid)
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func windowsTarget(t *testing.T) model.Target {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return model.Target{Executable: path}
}
func windowsOptions() Options { return Options{Timeout: 3 * time.Second, MaxOutput: 1024} }

func TestWindowsElevationRefused(t *testing.T) {
	elevated, err := Elevated()
	if err != nil {
		t.Fatal(err)
	}
	if !elevated {
		t.Log("non-elevated token confirmed")
		return
	}
	opts := windowsOptions()
	opts.AllowRoot = true
	out, err := Exec(context.Background(), windowsTarget(t), []string{"-test.run=TestWindowsProbeChild", "--", "env-child"}, nil, nil, opts)
	if !errors.Is(err, ErrElevatedDenied) || len(out.Stdout) > 0 {
		t.Fatal("elevated execution was not denied")
	}
	t.Log("elevated token denied even with root opt-in")
}

func TestWindowsEnvironmentAndDangerousOptions(t *testing.T) {
	t.Setenv("EMUDHRASLOP_TEST_SECRET", "must-not-reach-child")
	t.Setenv("NODE_OPTIONS", "--require=hostile.js")
	args := []string{"-test.run=TestWindowsProbeChild", "--", "env-child"}
	out, err := Exec(context.Background(), windowsTarget(t), args, nil, map[string]string{"SSL_CERT_FILE": `C:\declared\roots.pem`}, windowsOptions())
	if err != nil || string(out.Stdout) != `||C:\declared\roots.pem` {
		t.Fatalf("environment boundary failed: %v", err)
	}
	for _, env := range []map[string]string{{"NODE_OPTIONS": "--require=hostile.js"}, {"HTTPS_PROXY": "http://name:secret@proxy.example"}, {"SystemRoot": `C:\hostile`}} {
		out, err := Exec(context.Background(), windowsTarget(t), args, nil, env, windowsOptions())
		if err == nil || len(out.Stdout) > 0 {
			t.Fatal("unsafe environment executed")
		}
	}
}

func TestWindowsJobKillsDescendantsAndBoundsOutput(t *testing.T) {
	options := windowsOptions()
	options.Timeout = 1500 * time.Millisecond
	start := time.Now()
	out, err := Exec(context.Background(), windowsTarget(t), []string{"-test.run=TestWindowsProbeChild", "--", "tree-child"}, nil, nil, options)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("process deadline failed: %v", err)
	}
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(out.Stdout)))
	if parseErr != nil {
		t.Fatal("descendant was not actually started")
	}
	h, openErr := syscall.OpenProcess(0x00100000, false, uint32(pid)) // SYNCHRONIZE
	if openErr != nil && !errors.Is(openErr, syscall.Errno(87) /* ERROR_INVALID_PARAMETER: PID no longer exists */) {
		t.Fatal("cannot attest descendant termination")
	}
	if openErr == nil {
		defer syscall.CloseHandle(h)
		state, err := syscall.WaitForSingleObject(h, 1000)
		if err != nil || state != syscall.WAIT_OBJECT_0 {
			t.Fatal("descendant survived job termination")
		}
	}
	options.Timeout = 3 * time.Second
	options.MaxOutput = 64
	out, err = Exec(context.Background(), windowsTarget(t), []string{"-test.run=TestWindowsProbeChild", "--", "flood-child"}, nil, nil, options)
	if !errors.Is(err, ErrOutputLimit) || len(out.Stdout) > 64 || len(out.Stderr) > 64 {
		t.Fatalf("output not bounded: %v", err)
	}
}
