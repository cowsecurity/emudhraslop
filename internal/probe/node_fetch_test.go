package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/config"
	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

// Random certificates prevent a global/default fixture CA from hiding a broken
// trust check. The private key exists only in the bounded fixture server.
func nodeFetchFixture(t *testing.T, wrongHost bool, delay time.Duration) (*httptest.Server, string, string, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral fetch fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"fixture.invalid"}}
	if !wrongHost {
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	hits := new(atomic.Int32)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { time.Sleep(delay); return nil, nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return server, path, incident.Hash(der), hits
}

func executeFetchFixture(t *testing.T, target model.Target, server *httptest.Server, script string) runtimeObservation {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	observed, err := runtimeExecute(context.Background(), target, runtimeInput{Host: host, Port: port, Client: "fetch", Timeout: 2}, script, []string{"--eval"}, Options{ProbeTimeout: 4 * time.Second, MaxOutput: 65536})
	if err != nil {
		t.Fatal(err)
	}
	return observed
}

func TestNodeFetchRequiresItsOwnAuthorizedPeer(t *testing.T) {
	target := nativeTestTarget(t, "node", "fetch")
	server, ca, leaf, _ := nodeFetchFixture(t, false, 0)
	target.Environment = map[string]string{"NODE_EXTRA_CA_CERTS": ca}
	got := executeFetchFixture(t, target, server, nodeScript)
	if !got.Accepted || got.LeafSHA256 != leaf {
		t.Fatalf("trusted fetch socket not attributed: %+v", got)
	}
	target.Environment = nil
	got = executeFetchFixture(t, target, server, nodeScript)
	if got.Accepted || got.LeafSHA256 != "" || got.ErrorClass != "certificate_rejected" {
		t.Fatalf("untrusted fetch accepted: %+v", got)
	}
	wrong, wrongCA, _, _ := nodeFetchFixture(t, true, 0)
	target.Environment = map[string]string{"NODE_EXTRA_CA_CERTS": wrongCA}
	got = executeFetchFixture(t, target, wrong, nodeScript)
	if got.Accepted || got.LeafSHA256 != "" || got.ErrorClass != "certificate_rejected" {
		t.Fatalf("wrong hostname accepted: %+v", got)
	}
}

func TestNodeFetchDoesNotBorrowAnotherRequestsSocket(t *testing.T) {
	target := nativeTestTarget(t, "node", "fetch")
	untrusted, _, _, _ := nodeFetchFixture(t, false, 250*time.Millisecond)
	distractor, ca, _, hits := nodeFetchFixture(t, false, 0)
	target.Environment = map[string]string{"NODE_EXTRA_CA_CERTS": ca}
	// This is a second real fetch, with a trusted certificate, in the same process.
	// Its diagnostics arrive while the intended request waits for its untrusted
	// certificate. No TLS API, diagnostics event or fetch result is mocked.
	prefix := fmt.Sprintf("setTimeout(() => fetch(%q, {method:'HEAD'}).catch(() => {}), 0);\n", distractor.URL)
	got := executeFetchFixture(t, target, untrusted, prefix+nodeScript)
	if hits.Load() == 0 {
		t.Fatal("trusted distracting request did not execute")
	}
	if got.Accepted || got.LeafSHA256 != "" || got.ErrorClass != "certificate_rejected" {
		t.Fatalf("unrelated TLS acceptance borrowed by fetch: %+v", got)
	}
}

func TestNodeFetchMissingAPIAndPerRequestCAStayUnknown(t *testing.T) {
	target := nativeTestTarget(t, "node", "fetch")
	server, _, _, _ := nodeFetchFixture(t, false, 0)
	got := executeFetchFixture(t, target, server, "globalThis.fetch = undefined;\n"+nodeScript)
	if got.Accepted || got.ErrorClass != "unsupported_client" {
		t.Fatalf("missing native fetch misreported: %+v", got)
	}
	for _, target := range []model.Target{
		{Kind: "node", Client: "fetch", Executable: "/never/execute", CABundle: "/some/roots.pem"},
		{Kind: "node", Client: "fetch", Executable: "/never/execute", CADir: "/some/roots"},
	} {
		got := Node(context.Background(), target, &incident.Incident{}, Options{})
		if got.Status != model.Unknown || got.Reason != "unsupported_node_fetch_ca_configuration" {
			t.Fatalf("unsupported fetch CA reached execution: %+v", got)
		}
	}
}

func TestNodeTrustOptionsAgreeAtAllBoundaries(t *testing.T) {
	for _, flag := range []string{"--use-system-ca", "--use-bundled-ca", "--use-openssl-ca", "--no-use-system-ca", "--no-use-bundled-ca", "--no-use-openssl-ca"} {
		env := map[string]string{"NODE_OPTIONS": flag}
		if run.ValidateNodeOptions(flag) != nil || config.ValidateEnvironment(env) != nil || validateRuntimeEnvironment(env, "node") != nil {
			t.Fatalf("CA flag disagrees across boundaries: %s", flag)
		}
	}
	for _, value := range []string{"--require=/tmp/hook.js", "--use-system-ca --import=hook", "--use-openssl-ca\n--require hook", "--use-system-ca=true", "'--use-bundled-ca'"} {
		env := map[string]string{"NODE_OPTIONS": value}
		if run.ValidateNodeOptions(value) == nil || config.ValidateEnvironment(env) == nil || validateRuntimeEnvironment(env, "node") == nil {
			t.Fatal("unsafe/ambiguous Node flags accepted")
		}
	}
}

// A listening TCP port is not TLS evidence. The request must abort without a
// certificate/result even when the peer never completes its TLS handshake.
func TestNodeFetchTimeoutRemainsUnknown(t *testing.T) {
	target := nativeTestTarget(t, "node", "fetch")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			<-done
		}
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	got, err := runtimeExecute(context.Background(), target, runtimeInput{Host: host, Port: port, Client: "fetch", Timeout: 0.1}, nodeScript, []string{"--eval"}, Options{ProbeTimeout: 3 * time.Second, MaxOutput: 65536})
	if err != nil {
		t.Fatal(err)
	}
	if got.Accepted || got.LeafSHA256 != "" || got.ErrorClass != "timeout" {
		t.Fatalf("hanging peer became trust evidence: %+v", got)
	}
}
