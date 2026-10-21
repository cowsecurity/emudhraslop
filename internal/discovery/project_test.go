package discovery

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

func clearProjectTrust(t *testing.T) {
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

func makeProjectEnvironment(t *testing.T, root string, executable bool) string {
	t.Helper()
	dir, name := "bin", "python"
	if runtime.GOOS == "windows" {
		dir, name = "Scripts", "python.exe"
	}
	if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pyvenv.cfg"), []byte("home = /fixture/base\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, dir, name)
	if executable {
		if err := os.WriteFile(path, []byte("not executable code: inventory must never execute it"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func assertClientContexts(t *testing.T, targets []model.Target, executable string, metadata bool) {
	t.Helper()
	want := map[string]bool{"stdlib": false, "requests": false, "httpx": false, "botocore": false, "urllib3": false, "aiohttp": false}
	for _, target := range targets {
		if target.Executable != executable {
			continue
		}
		if previous, ok := want[target.Client]; !ok || previous {
			t.Fatalf("unexpected or duplicated Python client: %s", target.Client)
		}
		want[target.Client] = true
		if target.Source != "project-discovery" || target.MetadataOnly != metadata || target.UID == nil || target.GID == nil {
			t.Fatalf("lost context identity or uncertainty: %+v", target)
		}
	}
	for client, found := range want {
		if !found {
			t.Fatalf("client silently omitted: %s", client)
		}
	}
}

func TestProjectKeepsAllClientContextsWithoutExecutingOrRecursing(t *testing.T) {
	clearProjectTrust(t)
	project := t.TempDir()
	first := makeProjectEnvironment(t, filepath.Join(project, ".venv"), true)
	second := makeProjectEnvironment(t, filepath.Join(project, "env"), true)
	makeProjectEnvironment(t, filepath.Join(project, "nested", ".venv"), true)
	targets, coverage, err := Project(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 12 || coverage.Complete || len(coverage.Exclusions) == 0 {
		t.Fatalf("unexpected scope: contexts=%d coverage=%+v", len(targets), coverage)
	}
	assertClientContexts(t, targets, first, false)
	assertClientContexts(t, targets, second, false)
	ids := map[string]bool{}
	for _, target := range targets {
		if ids[target.ID] {
			t.Fatal("separate environments received duplicate IDs")
		}
		ids[target.ID] = true
	}
	direct, _, err := Project(filepath.Dir(filepath.Dir(first)))
	if err != nil || len(direct) != 6 {
		t.Fatal("selecting the virtual environment itself lost its clients")
	}
	for _, target := range direct {
		if !ids[target.ID] {
			t.Fatal("same environment received a different identity through its project")
		}
	}
}

func TestProjectPreservesMissingInterpreterAndUnsafeEnvironmentAsUnknown(t *testing.T) {
	clearProjectTrust(t)
	project := t.TempDir()
	missing := makeProjectEnvironment(t, filepath.Join(project, "venv"), false)
	targets, coverage, err := Project(project)
	if err != nil || len(targets) != 6 || len(coverage.Warnings) == 0 {
		t.Fatal("missing interpreter disappeared")
	}
	assertClientContexts(t, targets, missing, true)
	executable := makeProjectEnvironment(t, filepath.Join(project, "venv"), true)
	t.Setenv("HTTPS_PROXY", "http://name:private-value@proxy.example")
	targets, coverage, err = Project(project)
	if err != nil {
		t.Fatal(err)
	}
	assertClientContexts(t, targets, executable, true)
	for _, target := range targets {
		if len(target.Environment) != 0 {
			t.Fatal("unsafe environment was retained")
		}
	}
	if strings.Contains(strings.Join(coverage.Warnings, " "), "private-value") {
		t.Fatal("warning disclosed credentials")
	}
}

func TestProjectRejectsInvalidRootAndReportsEmptySelection(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "ordinary-file")
	if err := os.WriteFile(file, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(root, "missing"), file, "bad\x00path", "bad\npath", strings.Repeat("x", 4097)} {
		if _, _, err := Project(path); err == nil {
			t.Fatal("invalid project root accepted")
		}
	}
	targets, coverage, err := Project(root)
	if err != nil || len(targets) != 0 || !strings.Contains(strings.Join(coverage.Warnings, " "), "no Python virtual environment found") {
		t.Fatal("empty project selection was not explained")
	}
}
