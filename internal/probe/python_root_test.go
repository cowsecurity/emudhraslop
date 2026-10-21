//go:build !windows

package probe

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

func rootPython(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires actual root and a Python interpreter in the isolated root test container")
	}
	path, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("root fixture requires Python")
	}
	if err := run.TrustedPath(path); err != nil {
		t.Fatalf("fixture interpreter must pass the old executable-path gate: %v", err)
	}
	return path
}

func TestRootPythonCannotBypassDenialWithTrustedPathsOrAllowRoot(t *testing.T) {
	python := rootPython(t)
	root, dropped := uint32(0), uint32(65534)
	identities := []model.Target{
		{}, {UID: &root, GID: &root}, {UID: &root, GID: &dropped},
		{UID: &dropped}, {UID: &dropped, GID: &root},
	}
	for _, client := range pythonNativeClients {
		for _, identity := range identities {
			identity.Kind, identity.Client, identity.Executable = "python", client, python
			for _, allow := range []bool{false, true} {
				result := Check(context.Background(), identity, &incident.Incident{}, Options{
					AllowRoot: allow, ProbeTimeout: 2 * time.Second, MaxOutput: 65536,
				})
				if result.Status != model.Unknown || result.Reason != "root_python_execution_denied" || result.RuntimeVersion != "" {
					t.Fatalf("Python executed without a nonroot identity pair: client=%s optin=%t result=%+v", client, allow, result)
				}
			}
		}
	}
}

func TestRootPythonHostileVenvStartupIsNeverExecuted(t *testing.T) {
	python := rootPython(t)
	directory := t.TempDir()
	// This fixture has a trusted root-owned executable path but a writable
	// pyvenv.cfg selecting alternate encodings. The old -I -S path executes
	// its harmless marker before the intended probe can run.
	prepare := `import os, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
(root / "venv/bin").mkdir(parents=True)
(root / "venv/bin/python").symlink_to(sys.executable)
home = root / "alternate/bin"
home.mkdir(parents=True)
lib = root / ("alternate/lib/python%d.%d" % sys.version_info[:2])
lib.mkdir(parents=True)
shutil.copytree(pathlib.Path(os.__file__).parent / "encodings", lib / "encodings")
with (lib / "encodings/__init__.py").open("a") as file:
    file.write("\nimport _io\n_io.open(%r, 'w').write('startup executed')\n" % str(root / "startup-marker"))
(lib / "os.py").write_text("# standard library search landmark\n")
config = root / "venv/pyvenv.cfg"
config.write_text("home = " + str(home) + "\ninclude-system-site-packages = false\n")
config.chmod(0o666)
`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, python, "-I", "-S", "-c", prepare, directory).CombinedOutput(); err != nil {
		t.Fatalf("cannot prepare real Python startup fixture: %v: %s", err, output)
	}
	executable := filepath.Join(directory, "venv", "bin", "python")
	if err := run.TrustedPath(executable); err != nil {
		t.Fatalf("fixture must pass old trusted executable gate: %v", err)
	}
	root := uint32(0)
	target := model.Target{Kind: "python", Client: "stdlib", Executable: executable, UID: &root, GID: &root}
	// Establish that the attack is live, independently of the new guard. The
	// reduced alternate stdlib may fail after encodings; the marker is evidence.
	_, _ = run.Exec(ctx, target, []string{"-I", "-S", "-c", "pass"}, nil, nil,
		run.Options{AllowRoot: true, Timeout: 3 * time.Second, MaxOutput: 65536})
	marker := filepath.Join(directory, "startup-marker")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("hostile startup fixture did not execute; regression oracle is invalid")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	result := Check(ctx, target, &incident.Incident{}, Options{AllowRoot: true, ProbeTimeout: 3 * time.Second, MaxOutput: 65536})
	if result.Status != model.Unknown || result.Reason != "root_python_execution_denied" {
		t.Fatalf("root Python startup was not refused: %+v", result)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("production probe executed hostile Python startup code")
	}
}

func TestRootPythonExplicitNonrootIdentityStillExecutes(t *testing.T) {
	python := rootPython(t)
	uid, gid := uint32(65534), uint32(65534)
	target := model.Target{Kind: "python", Client: "stdlib", Executable: python, UID: &uid, GID: &gid}
	opts := Options{ProbeTimeout: 3 * time.Second, MaxOutput: 65536}
	result := Check(context.Background(), target, &incident.Incident{}, opts)
	if result.Status != model.Unknown || result.Reason != "offline_native_policy_not_proven" || !strings.HasPrefix(result.RuntimeVersion, "Python ") {
		t.Fatalf("explicit nonroot Python probe failed: %+v", result)
	}
	// Measure kernel execution identity with the same runner rather than
	// accepting a runtime version as evidence that privilege dropping worked.
	output, err := run.Exec(context.Background(), target,
		[]string{"-I", "-S", "-c", "import json,os; print(json.dumps([os.geteuid(), os.getegid(), os.getgroups()]))"},
		nil, nil, run.Options{Timeout: 3 * time.Second, MaxOutput: 65536})
	var observed []json.RawMessage
	if err != nil || json.Unmarshal(output.Stdout, &observed) != nil || len(observed) != 3 ||
		string(observed[0]) != "65534" || string(observed[1]) != "65534" || string(observed[2]) != "[]" {
		t.Fatalf("Python did not run solely as the declared identity: error=%v output=%s", err, output.Stdout)
	}
}
