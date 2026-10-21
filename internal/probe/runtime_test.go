package probe

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

func nativeTestTarget(t *testing.T, kind, client string) model.Target {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("native integration runs as non-root; root privilege paths tested by runner")
	}
	name := "node"
	if kind == "python" {
		name = "python3"
		if runtime.GOOS == "windows" {
			name = "python.exe"
		}
		if configured := os.Getenv("EMUDHRASLOP_TEST_PYTHON"); configured != "" {
			name = configured
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		if runtime.GOOS == "windows" {
			t.Fatal("required native runtime unavailable: " + name)
		}
		t.Skip("native runtime unavailable: " + name)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	return model.Target{ID: client, Kind: kind, Client: client, Executable: path, UID: &uid, GID: &gid, Source: "test"}
}

// This uses the real subprocess scripts and TLS library against a bounded local
// TLS fixture. The fixture is not represented as an eMudhra incident certificate.
func TestNativeRuntimeRequiresTrustedPeerAndReturnsExactCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	certificate := server.Certificate()
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	sum := sha256.Sum256(certificate.Raw)
	expected := hex.EncodeToString(sum[:])
	for _, entry := range []struct{ kind, client string }{{"python", "stdlib"}, {"python", "requests"}, {"python", "httpx"}, {"python", "botocore"}, {"node", "tls"}, {"node", "https"}} {
		t.Run(entry.kind+"/"+entry.client, func(t *testing.T) {
			target := nativeTestTarget(t, entry.kind, entry.client)
			script, args := pythonScript, []string{"-I", "-S", "-c"}
			if entry.kind == "python" && entry.client != "stdlib" {
				args = []string{"-I", "-c"}
			}
			if entry.kind == "node" {
				script, args = nodeScript, []string{"--eval"}
			}
			input := runtimeInput{Host: host, Port: port, Client: entry.client, Timeout: 2, CABundle: caPath}
			opts := Options{ProbeTimeout: 3 * time.Second, MaxOutput: 65536}
			accepted, err := runtimeExecute(context.Background(), target, input, script, args, opts)
			if err != nil {
				t.Fatal(err)
			}
			if accepted.ErrorClass == "package_unavailable" {
				if runtime.GOOS == "windows" {
					t.Fatal("required Windows integration client package unavailable")
				}
				t.Skip("optional client package unavailable in test interpreter")
			}
			if !accepted.Accepted || accepted.LeafSHA256 != expected {
				t.Fatalf("native trusted peer not attributed: %+v", accepted)
			}
			input.CABundle = ""
			rejected, err := runtimeExecute(context.Background(), target, input, script, args, opts)
			if err != nil {
				t.Fatal(err)
			}
			if rejected.Accepted || rejected.LeafSHA256 != "" || rejected.ErrorClass != "certificate_rejected" {
				t.Fatalf("untrusted certificate accepted or obscured: %+v", rejected)
			}
		})
	}
}

func TestRuntimeRejectsHooksAndCredentialBearingProxiesBeforeExecution(t *testing.T) {
	for _, environment := range []map[string]string{
		{"NODE_OPTIONS": "--require=/tmp/hostile.js"},
		{"NODE_OPTIONS": "--use-system-ca --import data:text/javascript,evil"},
		{"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
		{"HTTPS_PROXY": "https://username:secret@proxy.example:443"},
		{"https_proxy": "https://proxy.example/?secret=value"},
		{"PYTHONPATH": "/tmp/hostile"},
	} {
		target := model.Target{ID: "attacker", Kind: "node", Client: "tls", Executable: "/never/execute", Environment: environment}
		result := Node(context.Background(), target, &incident.Incident{}, Options{})
		if result.Status != model.Unknown || result.Reason == "runtime_probe_failed" {
			t.Fatalf("unsafe input reached execution: %+v", result)
		}
	}
}

func TestOfflineNativeEvidenceCannotBecomeProtection(t *testing.T) {
	for _, kind := range []string{"python", "node"} {
		t.Run(kind, func(t *testing.T) {
			client := "stdlib"
			if kind == "node" {
				client = "tls"
			}
			target := nativeTestTarget(t, kind, client)
			opts := Options{ProbeTimeout: 3 * time.Second, MaxOutput: 65536}
			var result model.Result
			if kind == "python" {
				result = Python(context.Background(), target, &incident.Incident{}, opts)
			} else {
				result = Node(context.Background(), target, &incident.Incident{}, opts)
			}
			if result.Status != model.Unknown || result.Reason != "offline_native_policy_not_proven" || result.RuntimeVersion == "" {
				t.Fatalf("offline result overclaimed or runtime failed: %+v", result)
			}
		})
	}
}

func TestNativeAcceptanceWithoutExactFixturePinIsNeverAffectedEvidence(t *testing.T) {
	expected := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, observation := range []runtimeObservation{
		{Accepted: true},
		{Accepted: true, LeafSHA256: "1234"},
		{Accepted: true, LeafSHA256: "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{Accepted: false, LeafSHA256: expected},
		{Accepted: false, ErrorClass: "certificate_rejected"},
		{Accepted: false, ErrorClass: "network_error"},
	} {
		if runtimePinnedAcceptance(observation, expected) {
			t.Fatalf("non-attributed observation became incident evidence: %+v", observation)
		}
	}
}

func TestMissingClientRemainsVisibleWithoutRepeatedIncidentProbes(t *testing.T) {
	target := nativeTestTarget(t, "python", "requests")
	in, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, online := range []bool{false, true} {
		// -S hides installed packages in the actual interpreter. This exercises
		// a real failed import, not a substitute subprocess result.
		result := runtimeProbe(context.Background(), target, in,
			Options{Online: online, ProbeTimeout: 3 * time.Second, MaxOutput: 65536}, pythonScript, []string{"-I", "-S", "-c"})
		if result.Status != model.Unknown || result.Reason != "package_unavailable" || len(result.Checks) != 0 || result.RuntimeVersion == "" {
			t.Fatalf("missing dependency hidden or repeatedly probed: %+v", result)
		}
	}
}
