package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func TestVenvConfigurationMutationInvalidatesSameInterpreterBytes(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(bin, "python")
	if err := os.WriteFile(executable, []byte("fingerprint fixture; never executed"), 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "pyvenv.cfg")
	if err := os.WriteFile(marker, []byte("include-system-site-packages = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	targets := []model.Target{{ID: "venv", Kind: "python", Executable: executable, Client: "requests"}}
	before, err := Fingerprint(targets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("include-system-site-packages = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := Fingerprint(targets)
	if err != nil || before == after {
		t.Fatal("changed venv configuration reused the same fingerprint")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	removed, err := Fingerprint(targets)
	if err != nil || removed == after || removed == before {
		t.Fatal("removed venv configuration reused a fingerprint")
	}
}
