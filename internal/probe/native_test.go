//go:build !windows

package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

func syntheticNativeChain(t *testing.T) (incident.Chain, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral native test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture.invalid"}, DNSNames: []string{"fixture.invalid"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return incident.Chain{ID: "ephemeral", Hostname: "fixture.invalid", LeafSHA256: incident.Hash(leafDER), Certificates: []*x509.Certificate{parsed, ca}, AffectedSPKIs: []string{incident.SPKI(ca)}}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

// This exercises the actual OpenSSL subprocess and its native verifier. The
// ephemeral test CA models a compromised key; no private key is saved to disk.
func TestOpenSSLNativeAcceptanceAndRejectionDoNotInventProtection(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root execution policy tested by runner tests")
	}
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL not installed")
	}
	chain, ca := syntheticNativeChain(t)
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if os.WriteFile(bundle, ca, 0600) != nil {
		t.Fatal("cannot write test bundle")
	}
	target := model.Target{ID: "openssl-fixture", Kind: "openssl", Executable: path, CABundle: bundle}
	opts := Options{ProbeTimeout: 5 * time.Second, MaxOutput: 65536}
	got := OpenSSL(context.Background(), target, &incident.Incident{Chains: []incident.Chain{chain}}, opts)
	if got.Status != model.Affected || len(got.Checks) != 1 || got.Checks[0].Outcome != "accepted" {
		t.Fatalf("native trusted fixture must be accepted: %+v", got)
	}
	_, other := syntheticNativeChain(t)
	if os.WriteFile(bundle, other, 0600) != nil {
		t.Fatal("cannot replace test bundle")
	}
	got = OpenSSL(context.Background(), target, &incident.Incident{Chains: []incident.Chain{chain}}, opts)
	if got.Status != model.Unknown || len(got.Checks) != 1 {
		t.Fatalf("native rejection is not a protection proof: %+v", got)
	}
}

func TestNativeFixtureRejectsWrongHashHostnameKeySignatureAndExpiry(t *testing.T) {
	chain, _ := syntheticNativeChain(t)
	if !nativeFixtureValid(chain) {
		t.Fatal("valid generated fixture rejected")
	}
	wrong := chain
	wrong.LeafSHA256 = incident.Hash([]byte("wrong"))
	if nativeFixtureValid(wrong) {
		t.Fatal("wrong leaf fingerprint accepted")
	}
	wrong = chain
	wrong.Hostname = "different.invalid"
	if nativeFixtureValid(wrong) {
		t.Fatal("wrong hostname accepted")
	}
	wrong = chain
	wrong.AffectedSPKIs = []string{incident.Hash([]byte("unrelated"))}
	if nativeFixtureValid(wrong) {
		t.Fatal("unrelated key accepted")
	}
	other, _ := syntheticNativeChain(t)
	wrong = chain
	wrong.Certificates = []*x509.Certificate{chain.Certificates[0], other.Certificates[1]}
	if nativeFixtureValid(wrong) {
		t.Fatal("invalid certificate signature accepted")
	}
	expired := *chain.Certificates[0]
	expired.NotAfter = time.Now().Add(-time.Second)
	wrong = chain
	wrong.Certificates = []*x509.Certificate{&expired, chain.Certificates[1]}
	if nativeFixtureValid(wrong) {
		t.Fatal("expired fixture accepted")
	}
}

func TestCurlPinsFirstLeafNotAReplacementChainOrSuccessText(t *testing.T) {
	chain, _ := syntheticNativeChain(t)
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.Certificates[0].Raw})
	other, _ := syntheticNativeChain(t)
	replacement := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Certificates[0].Raw})
	if !curlPinnedLeaf(append([]byte("Cert:"), leaf...), chain.LeafSHA256) {
		t.Fatal("exact first leaf rejected")
	}
	for _, data := range [][]byte{[]byte("TLS OK"), []byte("-----BEGIN CERTIFICATE-----broken"), append(replacement, leaf...)} {
		if curlPinnedLeaf(data, chain.LeafSHA256) {
			t.Fatal("missing or replacement leaf incorrectly identified as incident leaf")
		}
	}
}

func TestNativeOfflineCurlAndUnspecifiedOpenSSLAreUnknown(t *testing.T) {
	inc := &incident.Incident{}
	if got := Curl(context.Background(), model.Target{}, inc, Options{}); got.Status != model.Unknown {
		t.Fatal(got)
	}
	if got := OpenSSL(context.Background(), model.Target{}, inc, Options{}); got.Status != model.Unknown {
		t.Fatal(got)
	}
	if got := Curl(context.Background(), model.Target{VerificationDisabled: true}, inc, Options{}); got.Status != model.Affected {
		t.Fatal(got)
	}
}

func TestNativeWriteCannotFollowOrReplaceExistingFixture(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	fixture := filepath.Join(dir, "fixture")
	if os.WriteFile(victim, []byte("preserve"), 0600) != nil || os.Symlink(victim, fixture) != nil {
		t.Fatal("cannot prepare symlink attack")
	}
	if nativeWrite(model.Target{}, fixture, []byte("overwrite")) == nil {
		t.Fatal("followed attacker fixture symlink")
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "preserve" {
		t.Fatal("symlink target modified")
	}
	if os.Remove(fixture) != nil {
		t.Fatal("cannot remove fixture link")
	}
	if nativeWrite(model.Target{}, fixture, []byte("original")) != nil {
		t.Fatal("cannot create exclusive fixture")
	}
	if nativeWrite(model.Target{}, fixture, []byte("replacement")) == nil {
		t.Fatal("existing fixture overwritten")
	}
	data, err = os.ReadFile(fixture)
	if err != nil || string(data) != "original" {
		t.Fatal("existing fixture changed")
	}
}

func TestNativeDiagnosticsAndProxySecretsAreNotReported(t *testing.T) {
	if nativeVersion([]byte("curl 8.7.1 credential=secret\nmore diagnostics")) != "curl 8.7.1" {
		t.Fatal("raw version diagnostics leaked")
	}
	if nativeVersion([]byte("credential=secret")) != "" {
		t.Fatal("unrecognized diagnostics reported as version")
	}
	target := model.Target{Kind: "curl", Executable: "/must/not/execute", Environment: map[string]string{"HTTPS_PROXY": "https://user:secret@proxy.invalid"}}
	got := Curl(context.Background(), target, &incident.Incident{}, Options{Online: true})
	if got.Status != model.Unknown || got.Reason != "unsupported_proxy_configuration" {
		t.Fatalf("credential proxy reached native execution: %+v", got)
	}
}

func TestRootNativeFixtureParentIsNotWritableByDroppedIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root boundary requires root test environment")
	}
	inherited := t.TempDir()
	t.Setenv("TMPDIR", inherited)
	uid, gid := uint32(65534), uint32(65534)
	target := model.Target{UID: &uid, GID: &gid}
	dir, cleanup, err := nativeTemp(target)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if strings.HasPrefix(dir, inherited+string(os.PathSeparator)) {
		t.Fatal("privileged fixtures inherited untrusted TMPDIR")
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("public fixture directory permissions incorrect")
	}
	fixture := filepath.Join(dir, "fixture")
	if nativeWrite(target, fixture, []byte("public certificate")) != nil {
		t.Fatal("cannot write fixture")
	}
	info, err = os.Stat(fixture)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatal("public fixture permissions incorrect")
	}
	for _, path := range []string{dir, fixture} {
		info, _ := os.Stat(path)
		if info.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatal("fixture path ownership transferred to child")
		}
	}
	cache := filepath.Join(dir, "modules")
	if nativeCache(target, cache) != nil {
		t.Fatal("cannot prepare compiler cache")
	}
	info, _ = os.Stat(cache)
	if info.Sys().(*syscall.Stat_t).Uid != uid || info.Mode().Perm() != 0700 {
		t.Fatal("compiler cache not privately owned by child")
	}
	// Exercise the kernel boundary as the actual target identity. Inspecting
	// ownership alone would miss a runner that failed to drop privileges.
	victim := filepath.Join(inherited, "victim")
	if os.WriteFile(victim, []byte("preserve root file"), 0600) != nil {
		t.Fatal("cannot create attack target")
	}
	link := filepath.Join(dir, "attacker-link")
	attack := `set -eu
[ "$(id -u)" = 65534 ] && [ "$(id -g)" = 65534 ] || exit 20
[ "$(cat "$1")" = 'public certificate' ] || exit 21
if (printf overwrite > "$1") 2>/dev/null; then exit 22; fi
if rm "$1" 2>/dev/null; then exit 23; fi
if ln -s "$2" "$3" 2>/dev/null; then exit 24; fi
if mv "$1" "$1.moved" 2>/dev/null; then exit 25; fi
printf child-cache > "$4/child-write"
printf denied
`
	child := model.Target{Executable: "/bin/sh", UID: &uid, GID: &gid}
	out, err := run.Exec(context.Background(), child, []string{"-c", attack, "fixture-attack", fixture, victim, link, cache}, nil, nil, run.Options{Timeout: 5 * time.Second, MaxOutput: 4096})
	if err != nil || out.ExitCode != 0 || string(out.Stdout) != "denied" {
		t.Fatalf("dropped-identity attack was not denied correctly: exit=%d error=%v", out.ExitCode, err)
	}
	for path, want := range map[string]string{fixture: "public certificate", victim: "preserve root file", filepath.Join(cache, "child-write"): "child-cache"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("unexpected post-attack contents for %s", filepath.Base(path))
		}
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("dropped identity created fixture symlink")
	}
	if _, err := os.Lstat(fixture + ".moved"); !os.IsNotExist(err) {
		t.Fatal("dropped identity renamed fixture")
	}
}

func TestAppleNativeFixtures(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("EMUDHRASLOP_NATIVE_APPLE_TEST") != "1" {
		t.Skip("opt-in native Apple compiler integration")
	}
	inc, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	inc.Chains = inc.Chains[:1]
	got := Apple(context.Background(), model.Target{ID: "apple", Kind: "apple", Executable: "/usr/bin/swift"}, inc, Options{ProbeTimeout: 60 * time.Second, MaxOutput: 65536})
	if got.RuntimeVersion == "" || len(got.Checks) != 1 {
		t.Fatalf("native helper did not complete: %+v", got)
	}
	if got.Status == model.NotAffected {
		t.Fatal("unattributed rejection falsely called protection")
	}
	t.Logf("native SecTrust status=%s outcome=%s", got.Status, got.Checks[0].Outcome)
}
