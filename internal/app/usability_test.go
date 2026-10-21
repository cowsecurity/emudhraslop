package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func unknownManifest(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "services.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"services":[{"id":"uncovered-app","kind":"java"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNoArgumentsShowQuickstartWithoutWork(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}, {"help"}} {
		var out, stderr bytes.Buffer
		if code := Run(args, &out, &stderr); code != 0 || stderr.Len() != 0 {
			t.Fatalf("help exit=%d stderr=%s", code, &stderr)
		}
		for _, required := range []string{"emudhraslop check --online", "--agent", "--services services.json", "Exit codes:", "--cache PATH"} {
			if !strings.Contains(out.String(), required) {
				t.Fatalf("quickstart missing %q", required)
			}
		}
		if strings.Contains(out.String(), "Checked at:") || strings.Contains(out.String(), `"results"`) {
			t.Fatal("help ran a scan")
		}
	}
}

func TestAgentForcesJSONAndNoCacheWithoutEnablingNetwork(t *testing.T) {
	manifest := unknownManifest(t)
	for _, command := range []string{"check", "inventory"} {
		var out, stderr bytes.Buffer
		code := Run([]string{command, "--services", manifest, "--agent", "--json=false", "--no-cache=false"}, &out, &stderr)
		if code != 3 || stderr.Len() != 0 {
			t.Fatalf("exit=%d stderr=%s", code, &stderr)
		}
		var report model.Report
		if err := json.Unmarshal(out.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.SchemaVersion != model.SchemaVersion || !report.ValidAssessmentScope() || report.Affected != nil || len(report.Results) != 1 || report.Results[0].Affected != nil || report.Mode == "online" || len(report.Errors) != 0 {
			t.Fatalf("agent changed decision or performed unexpected work: %+v", report)
		}
	}
}

func TestAgentCannotSilentlyUseOrWriteCache(t *testing.T) {
	for _, args := range [][]string{
		{"check", "--agent", "--cache", "report.json"},
		{"check", "--cached", "--agent"},
		{"inventory", "--agent", "--cache", "report.json"},
		{"check", "--no-cache", "--cache", "report.json"},
	} {
		var out, stderr bytes.Buffer
		if code := Run(args, &out, &stderr); code != 1 || out.Len() != 0 {
			t.Fatalf("conflicting cache flags accepted: %v", args)
		}
	}
}

func TestCheckDoesNotWriteDefaultCache(t *testing.T) {
	// Unwritable/non-directory user cache location must not turn a fresh check
	// into a cache error, including on Windows where report caches are disabled.
	base := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(base, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", base)
	t.Setenv("LOCALAPPDATA", base)
	if runtime.GOOS == "darwin" {
		t.Setenv("HOME", base)
	}
	var out, stderr bytes.Buffer
	code := Run([]string{"check", "--services", unknownManifest(t), "--json"}, &out, &stderr)
	var report model.Report
	if code != 3 || json.Unmarshal(out.Bytes(), &report) != nil || len(report.Errors) != 0 {
		t.Fatalf("default check attempted cache access: exit=%d stderr=%s report=%s", code, &stderr, &out)
	}
}

func TestExplicitCacheStillWritesAndCachedStillReads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows report caches are intentionally unsupported")
	}
	manifest := unknownManifest(t)
	if os.Geteuid() == 0 {
		t.Skip("root-owned temporary ancestry is intentionally untrusted for report caches")
	}
	cacheDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	t.Setenv("HOME", cacheDir)
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	cachePath := filepath.Join(base, "emudhraslop", "report.json")
	for _, mode := range [][]string{{"--cache", cachePath}, {"--cached", "--cache", cachePath}, {"--cached"}} {
		var out, stderr bytes.Buffer
		args := append([]string{"check", "--services", manifest, "--json"}, mode...)
		code := Run(args, &out, &stderr)
		var report model.Report
		if code != 3 || json.Unmarshal(out.Bytes(), &report) != nil || len(report.Errors) != 0 {
			t.Fatalf("explicit cache broken: exit=%d stderr=%s report=%s", code, &stderr, &out)
		}
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatal(err)
	}
}

func TestRelativeManifestAcceptedAtCLI(t *testing.T) {
	manifest := unknownManifest(t)
	t.Chdir(filepath.Dir(manifest))
	var out, stderr bytes.Buffer
	if code := Run([]string{"inventory", "--services", "services.json", "--agent"}, &out, &stderr); code != 3 {
		t.Fatalf("relative manifest failed: exit=%d stderr=%s", code, &stderr)
	}
	var report model.Report
	if json.Unmarshal(out.Bytes(), &report) != nil || len(report.Results) != 1 || report.Results[0].ID != "uncovered-app" {
		t.Fatal("relative manifest did not load the declared target")
	}
}

func TestHumanReportRetainsUnknownsAndEscapesUntrustedText(t *testing.T) {
	report := model.Report{Incident: "incident", Mode: "online", Status: model.Affected,
		Coverage: model.Coverage{Scope: "managed", Exclusions: []string{"browsers"}, Warnings: []string{"warning\rhidden", "unicode\u009b2J"}},
		Errors:   []string{"future_error\x1b[2J"}, Results: []model.Result{
			{ID: "node", Kind: "node", Client: "tls", Executable: "/runtime/node\x1b[2J", RuntimeVersion: "v1\u202e", Status: model.Affected, Reason: "native_client_accepted_incident_fixture", NextAction: "update\nforged", TrustSources: []model.TrustSource{{Path: "/client/roots.pem\x1b[2J", Complete: true}, {Path: "/client/partial.pem", Complete: false}}},
			{ID: "unresolved", Kind: "openssl", Status: model.Unknown, Reason: "openssl_explicit_trust_context_required"},
			{ID: "future", Status: "new-status\t", Reason: "new_reason\x9b2J"},
			{ID: "protected", Status: model.NotAffected, Reason: "known_incident_tls_paths_not_trusted_by_explicit_openssl_bundle"},
		}}
	var out bytes.Buffer
	if err := emit(&out, report, false); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, required := range []string{"Client configurations: 4 total; 1 affected, 1 not affected, 2 unknown.", "node / tls", "/runtime/node\\x1b[2J", "Version: v1\\u202e", "(unresolved)", "(future)", "(protected)", "new-status\\t", "new_reason\\x9b2J", "Trust file: /client/roots.pem\\x1b[2J", "Trust file (incomplete evidence): /client/partial.pem", "Warning: warning\\rhidden", "Warning: unicode\\u009b2J", "Error: Check detail: future_error\\x1b[2J", "Not covered: browsers", "Coverage: incomplete", "Next: update\\nforged"} {
		if !strings.Contains(text, required) {
			t.Errorf("missing %q in:\n%s", required, text)
		}
	}
	if strings.ContainsAny(text, "\r\t\x1b\x9b\u202e") {
		t.Fatal("untrusted terminal controls survived rendering")
	}
	// Human escaping must never mutate the machine-readable evidence.
	out.Reset()
	if err := emit(&out, report, true); err != nil {
		t.Fatal(err)
	}
	var decoded model.Report
	if json.Unmarshal(out.Bytes(), &decoded) != nil || decoded.Results[0].Executable != report.Results[0].Executable {
		t.Fatal("JSON evidence changed while formatting human output")
	}
}

func TestUnknownReasonIsNotTurnedIntoProtection(t *testing.T) {
	for _, results := range [][]model.Result{nil, {{Status: model.Unknown, Reason: "future_reason"}}} {
		report := model.Report{Status: model.Unknown, Results: results, Coverage: model.Coverage{Complete: true}}
		var out bytes.Buffer
		if err := emit(&out, report, false); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(out.String(), "UNKNOWN:") || strings.Contains(out.String(), "NOT AFFECTED within") {
			t.Fatal("unknown scope rendered as protected")
		}
	}
}

func TestCachedOutputDoesNotSuggestConflictingAgentFlag(t *testing.T) {
	var out bytes.Buffer
	if err := emit(&out, model.Report{Mode: "cached", Status: model.Unknown}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "add --agent") || !strings.Contains(out.String(), "use --json") {
		t.Fatal("cached output recommends flags that cannot be combined")
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOutputFailurePropagatesAndBadFlagsDoNotInjectTerminalControls(t *testing.T) {
	if !errors.Is(emit(failedWriter{}, model.Report{}, false), io.ErrClosedPipe) || Run(nil, failedWriter{}, io.Discard) != 1 {
		t.Fatal("output failure hidden")
	}
	var out, stderr bytes.Buffer
	if code := Run([]string{"check", "--evil\x1b[2J"}, &out, &stderr); code != 1 || strings.ContainsRune(stderr.String(), '\x1b') {
		t.Fatal("invalid argument echoed terminal control")
	}
}
