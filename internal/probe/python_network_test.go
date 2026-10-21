package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRequestsDoesNotDrainRedirectBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.invalid/never-follow")
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusFound)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	input, expected := pythonTLSInput(t, server)
	input.Client, input.Timeout = "requests", 0.2
	observed := executePythonClient(t, nativeTestTarget(t, "python", input.Client), input)
	if !observed.Accepted || observed.LeafSHA256 != expected {
		t.Fatalf("redirect processing buffered the body or lost peer: %+v", observed)
	}
}

func TestPythonHTTPFailuresCannotSupplyAcceptance(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	input, _ := pythonTLSInput(t, server)
	input.Timeout = 0.1
	for _, client := range []string{"requests", "httpx", "botocore", "urllib3", "aiohttp"} {
		t.Run(client, func(t *testing.T) {
			input.Client = client
			observed := executePythonClient(t, nativeTestTarget(t, "python", client), input)
			if observed.Accepted || observed.LeafSHA256 != "" || observed.ErrorClass == "" {
				t.Fatalf("unfinished HTTP operation became acceptance: %+v", observed)
			}
		})
	}
}

func TestPythonCADirectoryActuallyContributesTrust(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl required to generate a platform-compatible hashed CA directory")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	input, expected := pythonTLSInput(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hashOutput, err := exec.CommandContext(ctx, openssl, "x509", "-in", input.CABundle, "-noout", "-subject_hash").Output()
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.TrimSpace(string(hashOutput))
	if !regexp.MustCompile(`^[a-f0-9]{8}$`).MatchString(hash) {
		t.Fatal("openssl returned an invalid subject hash")
	}
	pemBytes, err := os.ReadFile(input.CABundle)
	if err != nil {
		t.Fatal(err)
	}
	input.CADir = t.TempDir()
	if err := os.WriteFile(filepath.Join(input.CADir, hash+".0"), pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	input.CABundle = ""
	for _, client := range []string{"stdlib", "requests", "httpx", "urllib3", "aiohttp"} {
		t.Run(client, func(t *testing.T) {
			input.Client = client
			target := nativeTestTarget(t, "python", client)
			observed := executePythonClient(t, target, input)
			if !observed.Accepted || observed.LeafSHA256 != expected {
				t.Fatalf("declared directory trust was ignored: %+v", observed)
			}
			empty := input
			empty.CADir = t.TempDir()
			assertPythonRejection(t, executePythonClient(t, target, empty))
		})
	}
}
