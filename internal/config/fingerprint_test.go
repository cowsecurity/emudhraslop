package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func contextFile(t *testing.T, dir, name, data string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFingerprintTracksContentIdentityAndTrustOverrides(t *testing.T) {
	dir := t.TempDir()
	exe := contextFile(t, dir, "runtime", "executable-A")
	ca := contextFile(t, dir, "roots.pem", "roots-A")
	target := model.Target{ID: "api", Kind: "node", Executable: exe, CABundle: ca, Environment: map[string]string{"NODE_OPTIONS": "--use-system-ca"}}
	get := func() string {
		t.Helper()
		sum, err := Fingerprint([]model.Target{target})
		if err != nil {
			t.Fatal(err)
		}
		return sum
	}
	first := get()
	contextFile(t, dir, "roots.pem", "roots-B")
	if first == get() {
		t.Fatal("CA content replacement did not invalidate context")
	}
	second := get()
	target.Environment["NODE_OPTIONS"] = "--use-bundled-ca"
	if second == get() {
		t.Fatal("runtime policy change did not invalidate context")
	}
	third := get()
	contextFile(t, dir, "runtime", "executable-B")
	if third == get() {
		t.Fatal("executable content replacement did not invalidate context")
	}
	fourth := get()
	target.ImageDigest = "sha256:changed"
	if fourth == get() {
		t.Fatal("image identity change did not invalidate context")
	}
}

func TestFingerprintOrderDoesNotMatterAndMissingInputsNeverDisappear(t *testing.T) {
	dir := t.TempDir()
	a := model.Target{ID: "a", Executable: contextFile(t, dir, "a", "a")}
	b := model.Target{ID: "b", Executable: contextFile(t, dir, "b", "b")}
	one, err := Fingerprint([]model.Target{a, b})
	if err != nil {
		t.Fatal(err)
	}
	two, err := Fingerprint([]model.Target{b, a})
	if err != nil || one != two {
		t.Fatal("target ordering changes effective context")
	}
	b.CABundle = filepath.Join(dir, "missing")
	if _, err := Fingerprint([]model.Target{a, b}); err == nil {
		t.Fatal("missing CA silently omitted")
	}
}

func TestFingerprintDetectsSymlinkReplacementAndDirectoryMembership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink identity behavior is covered on Unix; Windows rejects reparse targets")
	}
	dir := t.TempDir()
	one := contextFile(t, dir, "one", "A")
	two := contextFile(t, dir, "two", "B")
	link := filepath.Join(dir, "current")
	if err := os.Symlink(one, link); err != nil {
		t.Fatal(err)
	}
	target := model.Target{ID: "api", Executable: link}
	a, err := Fingerprint([]model.Target{target})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(two, link); err != nil {
		t.Fatal(err)
	}
	b, err := Fingerprint([]model.Target{target})
	if err != nil || a == b {
		t.Fatal("symlink changed without invalidation")
	}
	trustdir := filepath.Join(dir, "trust")
	if err := os.Mkdir(trustdir, 0700); err != nil {
		t.Fatal(err)
	}
	target.CADir = trustdir
	c, err := Fingerprint([]model.Target{target})
	if err != nil {
		t.Fatal(err)
	}
	contextFile(t, trustdir, "root.pem", "root")
	d, err := Fingerprint([]model.Target{target})
	if err != nil || c == d {
		t.Fatal("new trust directory member did not invalidate context")
	}
	if err := os.Mkdir(filepath.Join(trustdir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Fingerprint([]model.Target{target}); err == nil {
		t.Fatal("nested trust source silently excluded")
	}
}

func TestFingerprintRejectsOversizedFilesBeforeReading(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "huge"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.Truncate(maxCABytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, err = Fingerprint([]model.Target{{ID: "api", CABundle: f.Name()}}); err == nil {
		t.Fatal("oversized trust bundle accepted")
	}
}
