//go:build !windows

package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/run"
)

func cleanTrustEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if run.AllowedEnvironment(key) {
			t.Setenv(key, "")
			if err := os.Unsetenv(key); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestManagedDiscoveryDeduplicatesSymlinksWithoutExecutingThem(t *testing.T) {
	cleanTrustEnvironment(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	exe := filepath.Join(dir, "python3")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "python")); err != nil {
		t.Fatal(err)
	}
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+dir)
	targets, coverage := Managed()
	found := 0
	for _, target := range targets {
		if target.Executable == exe {
			found++
			if target.UID == nil || target.GID == nil || *target.UID != uint32(os.Geteuid()) {
				t.Fatal("discovery lost execution identity")
			}
		}
	}
	if found != 1 {
		t.Fatalf("expected one context for alias pair, got %d", found)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("inventory executed discovered program")
	}
	if coverage.Complete || len(coverage.Exclusions) == 0 {
		t.Fatal("managed discovery claimed whole-machine coverage")
	}
}

func TestUnsafeEnvironmentRemainsVisibleRatherThanBecomingCleanContext(t *testing.T) {
	cleanTrustEnvironment(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "node")
	if err := os.WriteFile(exe, []byte("unused"), 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("HTTPS_PROXY", "http://name:do-not-leak@proxy.example")
	targets, coverage := Managed()
	found := false
	for _, target := range targets {
		if target.Executable == exe {
			found = true
			if !target.MetadataOnly || len(target.Environment) != 0 {
				t.Fatal("unsafe environment became executable context or retained credentials")
			}
		}
	}
	if !found || len(coverage.Warnings) == 0 {
		t.Fatal("unsupported context disappeared")
	}
	for _, warning := range coverage.Warnings {
		if strings.Contains(warning, "do-not-leak") {
			t.Fatal("warning disclosed proxy credential")
		}
	}
}

func TestRelativeAndExcessPATHEntriesProduceCoverageWarnings(t *testing.T) {
	cleanTrustEnvironment(t)
	t.Setenv("PATH", "relative"+strings.Repeat(string(os.PathListSeparator)+"/missing", maxPATHDirectories+1))
	_, coverage := Managed()
	joined := strings.Join(coverage.Warnings, " ")
	if !strings.Contains(joined, "limit reached") || !strings.Contains(joined, "relative PATH") {
		t.Fatal("PATH omissions were hidden")
	}
}
