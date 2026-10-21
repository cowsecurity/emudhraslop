//go:build !windows

package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func shellTarget() model.Target {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	return model.Target{Executable: "/bin/sh", UID: &uid, GID: &gid}
}

func options() Options {
	return Options{Timeout: 2 * time.Second, MaxOutput: 1024, AllowRoot: os.Geteuid() == 0}
}

func TestInheritedSecretsNeverReachChild(t *testing.T) {
	t.Setenv("EMUDHRASLOP_TEST_SECRET", "not-for-child")
	t.Setenv("NODE_OPTIONS", "--require /hostile.js")
	out, err := Exec(context.Background(), shellTarget(), []string{"-c", `printf '%s|%s|%s' "$EMUDHRASLOP_TEST_SECRET" "$NODE_OPTIONS" "$SSL_CERT_FILE"`}, nil, map[string]string{"SSL_CERT_FILE": "/declared/roots.pem"}, options())
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Stdout) != "||/declared/roots.pem" {
		t.Fatalf("ambient values crossed boundary: %q", out.Stdout)
	}
}

func TestPreloadHooksProxyCredentialsAndInjectionRejectedBeforeExecution(t *testing.T) {
	cases := []map[string]string{
		{"NODE_OPTIONS": "--require /hostile.js"},
		{"NODE_OPTIONS": "--use-system-ca --import=hostile"},
		{"NODE_OPTIONS": "--use-system-ca\t-r\thostile"},
		{"NODE_OPTIONS": "--use-system-ca='--require x'"},
		{"HTTPS_PROXY": "http://user:password@proxy.example:8080"},
		{"http_proxy": "http://proxy.example/?token=secret"},
		{"ALL_PROXY": "file:///private/secret"},
		{"SSL_CERT_FILE": "/ca\nINJECTED=value"},
		{"TOKEN_SECRET": "hidden"},
		{"NODE_TLS_REJECT_UNAUTHORIZED": "unexpected"},
	}
	for _, env := range cases {
		out, err := Exec(context.Background(), shellTarget(), []string{"-c", "printf executed"}, nil, env, options())
		if err == nil || len(out.Stdout) > 0 {
			t.Fatalf("unsafe environment executed: %v", env)
		}
		if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "secret") {
			t.Fatalf("error disclosed environment: %v", err)
		}
	}
}

func TestSupportedTrustFlagsAndUnauthenticatedProxyPreserved(t *testing.T) {
	env := map[string]string{"NODE_OPTIONS": "--use-system-ca --use-openssl-ca", "HTTPS_PROXY": "http://proxy.example:8080"}
	out, err := Exec(context.Background(), shellTarget(), []string{"-c", `printf '%s|%s' "$NODE_OPTIONS" "$HTTPS_PROXY"`}, nil, env, options())
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Stdout) != "--use-system-ca --use-openssl-ca|http://proxy.example:8080" {
		t.Fatal("declared trust policy changed")
	}
}

func TestOutputFloodIsBoundedAndNotReportedAsSuccess(t *testing.T) {
	opts := options()
	opts.MaxOutput = 64
	out, err := Exec(context.Background(), shellTarget(), []string{"-c", "i=0; while [ $i -lt 10000 ]; do printf flood-output; i=$((i+1)); done"}, nil, nil, opts)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("expected output limit, got %v", err)
	}
	if len(out.Stdout) > 64 || len(out.Stderr) > 64 {
		t.Fatal("output cap exceeded")
	}
}

func TestTimeoutKillsDescendantsHoldingPipes(t *testing.T) {
	opts := options()
	opts.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, err := Exec(context.Background(), shellTarget(), []string{"-c", "sleep 5 & wait"}, nil, nil, opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("descendant process retained pipes after timeout")
	}
}

func TestRootAndOtherExecutionIdentitiesRequireExplicitAuthority(t *testing.T) {
	target := shellTarget()
	opts := options()
	if os.Geteuid() == 0 {
		opts.AllowRoot = false
		if _, err := Exec(context.Background(), target, []string{"-c", "true"}, nil, nil, opts); !errors.Is(err, ErrRootDenied) {
			t.Fatalf("implicit root probe: %v", err)
		}
		uid := uint32(65534)
		target.UID = &uid
		target.GID = nil
		if _, err := Exec(context.Background(), target, []string{"-c", "true"}, nil, nil, opts); err == nil {
			t.Fatal("root dropped uid without explicit gid")
		}
	} else {
		uid := uint32(os.Geteuid() + 1)
		target.UID = &uid
		if _, err := Exec(context.Background(), target, []string{"-c", "true"}, nil, nil, opts); err == nil {
			t.Fatal("unauthorized execution identity accepted")
		}
	}
}

func TestWritableAndSymlinkedManagedExecutablePathsRejected(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "probe")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0777); err != nil {
		t.Fatal(err)
	}
	if err := TrustedPath(script); err == nil {
		t.Fatal("writable managed executable trusted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	if err := TrustedPath(link); err == nil && os.Geteuid() != 0 {
		t.Fatal("user-owned symlink ancestry trusted for root")
	}
}

func TestInvalidResourceLimitsNeverLaunch(t *testing.T) {
	for _, opts := range []Options{{Timeout: time.Second}, {MaxOutput: 1}} {
		out, err := Exec(context.Background(), shellTarget(), []string{"-c", "printf ran"}, nil, nil, opts)
		if err == nil || len(out.Stdout) > 0 {
			t.Fatal("unbounded subprocess started")
		}
	}
}

func TestRequestedGroupCannotSilentlyUseInheritedGroup(t *testing.T) {
	target := shellTarget()
	gid := uint32(os.Getegid() + 1)
	target.GID = &gid
	out, err := Exec(context.Background(), target, []string{"-c", "printf ran"}, nil, nil, options())
	if err == nil || len(out.Stdout) > 0 {
		t.Fatal("unsupported group was silently ignored")
	}
}

func TestRootDropsToExplicitServiceUIDGIDAndClearsSupplementaryGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise real credential dropping")
	}
	uid, gid := uint32(65534), uint32(65534)
	target := model.Target{Executable: "/bin/sh", UID: &uid, GID: &gid}
	// An ambient temporary directory must not control root's child workspace.
	hostile := t.TempDir()
	t.Setenv("TMPDIR", hostile)
	script := `test "$PWD" -ef "$HOME" || exit 21
test -w "$HOME" || exit 22
case "$HOME" in /tmp/emudhraslop-probe-*) ;; *) exit 23 ;; esac
printf '%s\n' "$(id -u)" "$(id -g)" "$(id -G)"`
	out, err := Exec(context.Background(), target, []string{"-c", script}, nil, nil, Options{Timeout: 2 * time.Second, MaxOutput: 1024})
	if err != nil {
		t.Fatalf("service identity execution failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out.Stdout)), "\n")
	if len(lines) != 3 || lines[0] != "65534" || lines[1] != "65534" {
		t.Fatalf("incorrect effective service identity: %q", out.Stdout)
	}
	groups := strings.Fields(lines[2])
	if len(groups) == 0 {
		t.Fatal("effective group observation missing")
	}
	for _, group := range groups {
		if group != "65534" {
			t.Fatalf("inherited supplementary group retained: %q", lines[2])
		}
	}
	t.Log("root-to-service UID/GID 65534 execution and empty inherited supplementary groups confirmed")
}
