package probe

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

func TestWindowsCurlUsesNativeVerificationAndPinnedPeer(t *testing.T) {
	path, err := exec.LookPath("curl.exe")
	if err != nil {
		t.Fatal("required Windows curl unavailable")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	target := model.Target{Executable: path}
	args := []string{"--disable", "--silent", "--proto", "=https", "--max-redirs", "0", "--max-time", "3", "--output", os.DevNull, "--write-out", "%{certs}", "--cacert", ca, "--url", server.URL}
	opts := run.Options{Timeout: 4 * time.Second, MaxOutput: 65536}
	out, err := run.Exec(context.Background(), target, args, nil, nil, opts)
	if err != nil || !curlPinnedLeaf(out.Stdout, incident.Hash(server.Certificate().Raw)) {
		t.Fatalf("native curl did not verify and attribute trusted peer: %v", err)
	}
	args = append(args[:len(args)-4], "--url", server.URL)
	out, err = run.Exec(context.Background(), target, args, nil, nil, opts)
	if err == nil || out.ExitCode == 0 {
		t.Fatal("native curl accepted untrusted fixture")
	}
}
