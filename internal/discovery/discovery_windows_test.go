package discovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsDiscoveryFindsExeWithoutExecutingAndWarnsCoverage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.exe")
	if err := os.WriteFile(path, []byte("not an executable; inventory must not run it"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+dir)
	targets, coverage := Managed()
	if len(targets) != 3 || targets[0].Kind != "node" || !strings.EqualFold(targets[0].Executable, path) {
		t.Fatal("Windows executable discovery failed")
	}
	if coverage.Complete || len(coverage.Exclusions) == 0 || len(coverage.Warnings) == 0 {
		t.Fatal("Windows coverage gaps hidden")
	}
}

func TestWindowsProjectRejectsRemoteDeviceAndStreamPaths(t *testing.T) {
	for _, path := range []string{`\\server-does-not-exist.invalid\share`, `\\.\pipe\test`, `\\?\C:\project`, `C:\project:stream`, `C:\NUL`} {
		if targets, _, err := Project(path); err == nil || len(targets) != 0 {
			t.Fatal("unsupported project path reached discovery")
		}
	}
}
