package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

var pythonNativeClients = []string{"stdlib", "requests", "httpx", "botocore", "urllib3", "aiohttp"}

// All adapters use the real selected interpreter and HTTP library. CA trust,
// hostname checking and peer attribution cannot be replaced by a mock oracle.
func TestPythonClientsVerifyActualConnection(t *testing.T) {
	var redirected atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer sink.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", sink.URL)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	input, expected := pythonTLSInput(t, server)
	for _, client := range pythonNativeClients {
		t.Run(client, func(t *testing.T) {
			target := nativeTestTarget(t, "python", client)
			trusted := input
			trusted.Client = client
			observed := executePythonClient(t, target, trusted)
			if !observed.Accepted || observed.LeafSHA256 != expected {
				t.Fatalf("verified response not attributed to its own certificate: %+v", observed)
			}
			if redirected.Load() != 0 {
				t.Fatal("client followed the fixture redirect")
			}
			untrusted := trusted
			untrusted.CABundle = ""
			assertPythonRejection(t, executePythonClient(t, target, untrusted))
			wrongName := trusted
			// httptest's certificate trusts 127.0.0.1 but not localhost.
			wrongName.Host = "localhost"
			assertPythonRejection(t, executePythonClient(t, target, wrongName))
		})
	}
}

func TestPythonClientsRetainUnknownOnMissingPackages(t *testing.T) {
	for _, client := range pythonNativeClients[1:] {
		t.Run(client, func(t *testing.T) {
			target := nativeTestTarget(t, "python", client)
			// -S deliberately hides site-packages to exercise a missing dependency
			// without installing or uninstalling anything in the user's runtime.
			observed, err := runtimeExecute(context.Background(), target, runtimeInput{Client: client}, pythonScript,
				[]string{"-I", "-S", "-c"}, Options{ProbeTimeout: 5 * time.Second, MaxOutput: 65536})
			if err != nil {
				t.Fatal(err)
			}
			if observed.Accepted || observed.LeafSHA256 != "" || observed.ErrorClass != "package_unavailable" {
				t.Fatalf("missing package became a trust decision: %+v", observed)
			}
		})
	}
}

func TestPythonUnsupportedTrustInputsNeverExecute(t *testing.T) {
	for _, target := range []model.Target{
		{Kind: "python", Client: "requests", CABundle: "/bundle", CADir: "/directory"},
		{Kind: "python", Client: "aiohttp", Environment: map[string]string{"HTTPS_PROXY": "http://proxy.example"}},
		{Kind: "python", Client: "urllib3", Environment: map[string]string{"https_proxy": "http://proxy.example"}},
	} {
		target.Executable = "/must/not/execute"
		result := Python(context.Background(), target, &incident.Incident{}, Options{})
		if result.Status != model.Unknown || (result.Reason != "unsupported_configuration" && result.Reason != "unsupported_proxy_configuration") {
			t.Fatalf("unsupported inputs silently ignored or executed: %+v", result)
		}
	}
}

func TestPythonNewClientsLoadBothDeclaredCASources(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	input, expected := pythonTLSInput(t, server)
	input.CADir = t.TempDir()
	for _, client := range []string{"urllib3", "aiohttp"} {
		t.Run(client, func(t *testing.T) {
			input.Client = client
			observed := executePythonClient(t, nativeTestTarget(t, "python", client), input)
			if !observed.Accepted || observed.LeafSHA256 != expected || len(observed.Sources) != 2 {
				t.Fatalf("declared CA bundle/directory lost: %+v", observed)
			}
		})
	}
}

func pythonTLSInput(t *testing.T, server *httptest.Server) (runtimeInput, string) {
	t.Helper()
	certificate := server.Certificate()
	caPath := filepath.Join(t.TempDir(), "fixture.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	sum := sha256.Sum256(certificate.Raw)
	return runtimeInput{Host: host, Port: port, Timeout: 2, CABundle: caPath}, hex.EncodeToString(sum[:])
}

func executePythonClient(t *testing.T, target model.Target, input runtimeInput) runtimeObservation {
	t.Helper()
	args := []string{"-I", "-c"}
	if target.Client == "stdlib" {
		args = []string{"-I", "-S", "-c"}
	}
	observed, err := runtimeExecute(context.Background(), target, input, pythonScript, args,
		Options{ProbeTimeout: 5 * time.Second, MaxOutput: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if observed.ErrorClass == "package_unavailable" {
		if os.Getenv("EMUDHRASLOP_TEST_PYTHON") != "" {
			t.Fatal("required client missing from explicitly configured test interpreter")
		}
		t.Skip("optional client missing; configure EMUDHRASLOP_TEST_PYTHON with tests/python-requirements.txt")
	}
	return observed
}

func assertPythonRejection(t *testing.T, observed runtimeObservation) {
	t.Helper()
	if observed.Accepted || observed.LeafSHA256 != "" || observed.ErrorClass != "certificate_rejected" {
		t.Fatalf("untrusted or wrong-host certificate accepted/obscured: %+v", observed)
	}
}
