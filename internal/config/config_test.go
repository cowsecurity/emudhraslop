//go:build !windows

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func writeManifest(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "services.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManifestRejectsAmbiguousSecuritySettingsWithoutEchoingInput(t *testing.T) {
	secret := "do-not-leak-token"
	cases := []string{
		`{"schema_version":1,"schema_version":1,"services":[]}`,
		`{"schema_version":1,"SCHEMA_VERSION":2,"services":[]}`,
		`{"SCHEMA_VERSION":1,"services":[{"id":"api","kind":"node","executable":"/usr/bin/node"}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"/usr/bin/node","environment":{"NODE_OPTIONS":"--use-system-ca","NODE_OPTIONS":"--require ` + secret + `"}}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"/usr/bin/node","unknown":"` + secret + `"}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"/usr/bin/node","environment":{"HTTPS_PROXY":"http://user:` + secret + `@proxy.example"}}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"/usr/bin/node","environment":{"NODE_OPTIONS":"--import=` + secret + `"}}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"node"}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"/tmp/../bin/node"}]}`,
		`{"schema_version":1,"services":[{"id":"api","kind":"node","executable":"/usr/bin/node"},{"id":"api","kind":"curl","executable":"/usr/bin/curl"}]}`,
		`{"schema_version":1,"services":[]} {"ignored":"` + secret + `"}`,
	}
	for _, data := range cases {
		t.Run(data[:min(len(data), 80)], func(t *testing.T) {
			_, err := Load(writeManifest(t, data))
			if err == nil {
				t.Fatal("accepted ambiguous or unsafe manifest")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error leaked supplied secret")
			}
		})
	}
}

func TestManifestPreservesUnsupportedContextsAndDisabledVerification(t *testing.T) {
	targets, err := Load(writeManifest(t, `{"schema_version":1,"services":[{"id":"browser","kind":"electron"},{"id":"api","kind":"node","executable":"/usr/bin/node","environment":{"NODE_OPTIONS":"--use-system-ca","NODE_TLS_REJECT_UNAUTHORIZED":"0"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !targets[0].MetadataOnly || targets[0].Source != "service-manifest" {
		t.Fatal("unsupported context lost or not marked incomplete")
	}
	if !targets[1].VerificationDisabled || targets[1].MetadataOnly || targets[1].UID == nil || targets[1].GID == nil {
		t.Fatal("known unsafe verification setting or identity lost")
	}
}

func TestManifestBoundsRejectInsteadOfTruncating(t *testing.T) {
	services := make([]model.Target, MaxTargets+1)
	for i := range services {
		services[i] = model.Target{ID: "unused", Kind: "node", Executable: "/usr/bin/node"}
	}
	data, _ := json.Marshal(manifest{SchemaVersion: 1, Services: services})
	if _, err := Load(writeManifest(t, string(data))); err == nil {
		t.Fatal("too many targets accepted")
	}
	if _, err := Load(writeManifest(t, strings.Repeat(" ", MaxManifestBytes+1))); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestManifestFIFORejectsWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Load(path); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("untrusted FIFO blocked manifest loading")
	}
}

func TestEnvironmentRejectsExecutionAndProxyCredentialVariants(t *testing.T) {
	for key, values := range map[string][]string{
		"NODE_OPTIONS":  {"--require=/tmp/payload.js", "--eval=process.exit()", "--use-system-ca --openssl-config=/tmp/config", "'--use-system-ca'"},
		"HTTPS_PROXY":   {"https://proxy.example/?token=secret", "http://user@proxy.example", "http://proxy.example/#secret", "file:///tmp/proxy"},
		"SSL_CERT_FILE": {"relative.pem", "/tmp/../etc/ca.pem", "/tmp/ca\n.pem"},
		"NO_PROXY":      {"host@secret", "https://private.example"},
	} {
		for _, value := range values {
			if ValidateEnvironment(map[string]string{key: value}) == nil {
				t.Fatalf("unsafe environment accepted for %s", key)
			}
		}
	}
	if err := ValidateEnvironment(map[string]string{"NODE_OPTIONS": "--use-system-ca --use-bundled-ca", "HTTPS_PROXY": "http://proxy.example:8080", "SSL_CERT_DIR": "/etc/ssl/certs:/usr/local/share/ca-certificates"}); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveCAFilePolicyMustBeExplicitAndCompatible(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "services.json")
	base := `{"schema_version":1,"services":[{"id":"explicit","kind":"openssl","executable":"/usr/bin/openssl","ca_bundle":"/etc/ssl/cert.pem","exclusive_ca_bundle":true}]}`
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	targets, err := Load(path)
	if err != nil || !targets[0].ExclusiveCABundle {
		t.Fatalf("explicit exclusive policy lost: %v", err)
	}
	for _, bad := range []string{strings.Replace(base, `"kind":"openssl"`, `"kind":"python"`, 1), strings.Replace(base, `"ca_bundle":"/etc/ssl/cert.pem",`, "", 1), strings.Replace(base, `"exclusive_ca_bundle":true`, `"exclusive_ca_bundle":true,"ca_dir":"/etc/ssl/certs"`, 1)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatal("incompatible exclusive trust claim accepted")
		}
	}
}
