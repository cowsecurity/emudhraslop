//go:build !windows

package probe

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

func nativeOpenSSL3(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("run native tests as non-root, including inside the container")
	}
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is unavailable")
	}
	version, err := exec.Command(path, "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "OpenSSL 3.") {
		t.Skip("negative proof requires actual OpenSSL 3")
	}
	return path
}

func nativeControlCA(t *testing.T) []byte {
	t.Helper()
	_, ca := syntheticNativeChain(t)
	certs, err := incident.ParsePEM(ca)
	if err != nil || certs[0].KeyUsage != x509.KeyUsageCertSign {
		t.Fatal("control must model an ordinary signing-only root, not a TLS leaf")
	}
	return ca
}

func TestOpenSSL3ExplicitBundleConfirmsOnlyCompleteKnownIncidentPaths(t *testing.T) {
	path := nativeOpenSSL3(t)
	inc, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = inc.Validate(time.Now()); err != nil {
		t.Fatalf("published fixtures cannot support a current negative proof: %v", err)
	}
	unrelatedCA := nativeControlCA(t)
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, unrelatedCA, 0600); err != nil {
		t.Fatal(err)
	}
	target := model.Target{ID: "explicit-openssl-file", Kind: "openssl", Executable: path, CABundle: bundle, ExclusiveCABundle: true}
	opts := Options{ProbeTimeout: 5 * time.Second, MaxOutput: 65536}
	got := OpenSSL(context.Background(), target, inc, opts)
	if got.Status != model.NotAffected || !got.ControlOK || len(got.Checks) != len(inc.Chains) || len(got.TrustSources) != 1 || !got.TrustSources[0].Complete {
		out, err := exec.Command(path, "verify", "-purpose", "any", "-check_ss_sig", "-no-CApath", "-no-CAstore", "-CAfile", bundle, bundle).CombinedOutput()
		t.Logf("synthetic native control diagnostics: %s (%v)", out, err)
		t.Fatalf("complete native proof failed: %+v", got)
	}
	for _, check := range got.Checks {
		if check.Outcome != "rejected" || check.Proof != "native_openssl_explicit_bundle_issuer_absent" {
			t.Fatalf("unattributed rejection was included in negative proof: %+v", check)
		}
	}
	// A successful control proves that the verifier still accepts the existing
	// bundle. No temporary CA was added to the target policy by the scanner.
	data, _ := os.ReadFile(bundle)
	if string(data) != string(unrelatedCA) || got.TrustSources[0].SHA256 != incident.Hash(data) {
		t.Fatal("probe changed the target CA policy or reported the wrong snapshot")
	}
	for name, change := range map[string]func(*model.Target, *incident.Incident){
		"implicit stores not excluded": func(target *model.Target, _ *incident.Incident) { target.ExclusiveCABundle = false },
		"omitted path":                 func(_ *model.Target, in *incident.Incident) { in.Chains = in.Chains[:len(in.Chains)-1] },
		"wrong manifest identity":      func(_ *model.Target, in *incident.Incident) { in.SHA256 = incident.Hash([]byte("other")) },
		"trust environment": func(target *model.Target, _ *incident.Incident) {
			target.Environment = map[string]string{"SSL_CERT_FILE": bundle}
		},
		"extra CA directory": func(target *model.Target, _ *incident.Incident) { target.CADir = t.TempDir() },
		"expired fixture": func(_ *model.Target, in *incident.Incident) {
			cert := *in.Chains[0].Certificates[0]
			cert.NotAfter = time.Now().Add(-time.Hour)
			in.Chains[0].Certificates = append([]*x509.Certificate{}, in.Chains[0].Certificates...)
			in.Chains[0].Certificates[0] = &cert
		},
	} {
		t.Run(name, func(t *testing.T) {
			copyTarget, copyIncident := target, *inc
			copyIncident.Chains = append([]incident.Chain{}, inc.Chains...)
			change(&copyTarget, &copyIncident)
			if got := OpenSSL(context.Background(), copyTarget, &copyIncident, opts); got.Status == model.NotAffected {
				t.Fatalf("incomplete or ambiguous evidence invented a negative confirmation: %+v", got)
			}
		})
	}
	untrustedLeaf, _ := syntheticNativeChain(t)
	unsuitableControl := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: untrustedLeaf.Certificates[0].Raw})
	if err := os.WriteFile(bundle, unsuitableControl, 0600); err != nil {
		t.Fatal(err)
	}
	if got := OpenSSL(context.Background(), target, inc, opts); got.Status != model.Unknown {
		t.Fatalf("an unsuitable positive control invented certainty: %+v", got)
	}
	// Trust expansion must invalidate the clean result, regardless of whether
	// this OpenSSL release already rejects one of the published leaves.
	expanded := append(append([]byte{}, unrelatedCA...), []byte(inc.Roots[0].PEM)...)
	if err := os.WriteFile(bundle, expanded, 0600); err != nil {
		t.Fatal(err)
	}
	if got := OpenSSL(context.Background(), target, inc, opts); got.Status == model.NotAffected {
		t.Fatalf("known issuer trust was hidden by fixture rejection: %+v", got)
	}
}

func TestOpenSSLBundleParserCannotHideKeysBehindPartialOrUnsupportedContents(t *testing.T) {
	_, ca := syntheticNativeChain(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	for _, data := range [][]byte{nil, append(append([]byte{}, ca...), []byte("garbage")...), []byte(strings.ReplaceAll(string(ca), "CERTIFICATE", "TRUSTED CERTIFICATE")), append([]byte("-----BEGIN CERTIFICATE-----\ninvalid first block\n"), ca...)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := opensslReadBundle(path); err == nil {
			t.Fatal("partial or unsupported CA file was treated as complete")
		}
	}
	commented := append([]byte("# complete CA bundle\n\n"), ca...)
	if err := os.WriteFile(path, commented, 0600); err != nil {
		t.Fatal(err)
	}
	if b, certs, err := opensslReadBundle(path); err != nil || len(certs) != 1 || string(b) != string(commented) {
		t.Fatal("ordinary comments or complete byte snapshot were not preserved")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(opensslBundleLimit + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := opensslReadBundle(path); err == nil {
		t.Fatal("oversized CA file treated as complete")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := opensslReadBundle(fifo); err == nil {
		t.Fatal("nonregular CA file accepted")
	}
}

func TestOpenSSLNegativePolicyDoesNotTrustInheritedManifestLabels(t *testing.T) {
	inc, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	_, ca := syntheticNativeChain(t)
	certs, err := incident.ParsePEM(ca)
	if err != nil {
		t.Fatal(err)
	}
	copyIncident := *inc
	copyIncident.Chains = append([]incident.Chain{}, inc.Chains...)
	replacement, _ := syntheticNativeChain(t)
	copyIncident.Chains[0].Certificates = replacement.Certificates
	copyIncident.Chains[0].AffectedSPKIs = replacement.AffectedSPKIs
	copyIncident.Chains[0].LeafSHA256 = replacement.LeafSHA256
	copyIncident.Chains[0].Hostname = replacement.Hostname
	if _, ok := opensslNegativePolicy(&copyIncident, certs); ok {
		t.Fatal("correct manifest label concealed replacement fixture bytes")
	}
}

func TestOpenSSL3DroppedIdentityCannotGainTrustFileAccessThroughSnapshot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-to-service boundary requires root container test environment")
	}
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL unavailable")
	}
	version, err := exec.Command(path, "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "OpenSSL 3.") {
		t.Skip("requires actual OpenSSL 3")
	}
	inc, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	var knownIssuers []byte
	for _, root := range inc.Roots {
		knownIssuers = append(knownIssuers, []byte(root.PEM)...)
	}
	uid, gid := uint32(65534), uint32(65534)
	bundle := filepath.Join(t.TempDir(), "restricted-ca.pem")
	target := model.Target{ID: "restricted-service", Kind: "openssl", Executable: path, CABundle: bundle, ExclusiveCABundle: true, UID: &uid, GID: &gid}
	for name, data := range map[string][]byte{"positive policy": knownIssuers, "negative policy": nativeControlCA(t)} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(bundle, data, 0600); err != nil {
				t.Fatal(err)
			}
			got := OpenSSL(context.Background(), target, inc, Options{ProbeTimeout: 5 * time.Second, MaxOutput: 65536})
			if got.Status != model.Unknown {
				t.Fatalf("snapshot manufactured a readable service context: %+v", got)
			}
		})
	}
}
