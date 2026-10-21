//go:build !windows

package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/config"
)

func TestManagedPreservesDifferentVenvsSharingOneBaseInterpreter(t *testing.T) {
	cleanTrustEnvironment(t)
	project := t.TempDir()
	base := filepath.Join(project, "base-python")
	if err := os.WriteFile(base, []byte("inventory cannot execute this"), 0700); err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	want := map[string]map[string]bool{}
	for _, name := range []string{"first", "second"} {
		executable := makeProjectEnvironment(t, filepath.Join(project, name), false)
		if err := os.Symlink(base, executable); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(base, filepath.Join(filepath.Dir(executable), "python3")); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, filepath.Dir(executable))
		want[filepath.Join(filepath.Dir(executable), "python3")] = map[string]bool{}
	}
	t.Setenv("PATH", strings.Join(paths, string(os.PathListSeparator)))
	targets, _ := Managed()
	for _, target := range targets {
		if clients, ok := want[target.Executable]; ok {
			if clients[target.Client] {
				t.Fatal("aliases produced a duplicate client context")
			}
			clients[target.Client] = true
		}
	}
	for executable, clients := range want {
		if len(clients) != 6 {
			t.Fatalf("venv collapsed to base interpreter or lost clients: %s -> %v", executable, clients)
		}
	}
}

func TestProjectDeduplicatesDirectoryAliasesButNotSeparateEnvironments(t *testing.T) {
	clearProjectTrust(t)
	project := t.TempDir()
	executable := makeProjectEnvironment(t, filepath.Join(project, ".venv"), true)
	if err := os.Symlink(filepath.Join(project, ".venv"), filepath.Join(project, "venv")); err != nil {
		t.Fatal(err)
	}
	targets, _, err := Project(project)
	if err != nil || len(targets) != 6 {
		t.Fatal("same virtual environment was duplicated through directory alias")
	}
	assertClientContexts(t, targets, executable, false)
}

func TestProjectDoesNotBlockOnFIFOConfigurationOrExecutable(t *testing.T) {
	project := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(project, "pyvenv.cfg"), 0600); err != nil {
		t.Fatal(err)
	}
	executable := makeProjectEnvironment(t, filepath.Join(project, ".venv"), false)
	if err := syscall.Mkfifo(executable, 0700); err != nil {
		t.Fatal(err)
	}
	targets, coverage, err := Project(project)
	if err != nil || len(targets) != 6 || len(coverage.Warnings) == 0 {
		t.Fatal("unsupported discovery file was accepted or hidden")
	}
	assertClientContexts(t, targets, executable, true)
}

func TestManagedContextLimitRemainsVisible(t *testing.T) {
	cleanTrustEnvironment(t)
	root := t.TempDir()
	paths := []string{}
	for index := 0; index < config.MaxTargets/6+2; index++ {
		directory := filepath.Join(root, fmt.Sprintf("runtime-%d", index))
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "python3"), []byte("inventory only"), 0700); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, directory)
	}
	t.Setenv("PATH", strings.Join(paths, string(os.PathListSeparator)))
	targets, coverage := Managed()
	if len(targets) != config.MaxTargets || coverage.Complete || !strings.Contains(strings.Join(coverage.Warnings, " "), "managed context limit reached") {
		t.Fatal("managed expansion exceeded its bound or hid omitted contexts")
	}
}
