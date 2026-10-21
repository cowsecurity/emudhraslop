package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

// Naming an isolated context after an application is not evidence about that
// application. Exercise the CLI, including config parsing and early decisions.
func TestServiceNameAndDeclaredSettingsCannotConfirmApplicationImpact(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, disabled := range []bool{false, true} {
		target := model.Target{ID: "production-api-port-443", Kind: "node", Executable: executable}
		if disabled {
			target.Environment = map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"}
		}
		manifest := filepath.Join(t.TempDir(), "services.json")
		data, err := json.Marshal(map[string]any{"schema_version": 1, "services": []model.Target{target}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifest, data, 0600); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"inventory", "check"} {
			args := []string{command, "--agent", "--services", manifest}
			if command == "check" && !disabled {
				args = append(args, "--timeout", "1ns")
			}
			var out, stderr bytes.Buffer
			code := Run(args, &out, &stderr)
			want := 3
			if disabled && command == "check" {
				want = 2
			}
			var report model.Report
			if code != want || json.Unmarshal(out.Bytes(), &report) != nil || !report.ValidAssessmentScope() {
				t.Fatalf("scope contract lost: code=%d out=%s err=%s", code, &out, &stderr)
			}
			basis := "client_defaults"
			if disabled {
				basis = "configured_client"
			}
			if report.Results[0].AssessmentBasis != basis {
				t.Fatalf("wrong tested context: %+v", report.Results[0])
			}
		}
	}
}

func TestProjectFlagsCannotSilentlyOmitInputs(t *testing.T) {
	var out, stderr bytes.Buffer
	for _, args := range [][]string{
		{"inventory", "--project", t.TempDir(), "--services", unknownManifest(t)},
		{"inventory", "--project", filepath.Join(t.TempDir(), "missing")},
		{"inventory", "--project", ""},
	} {
		out.Reset()
		stderr.Reset()
		if code := Run(args, &out, &stderr); code != 1 || out.Len() != 0 {
			t.Fatalf("invalid project accepted: %v", args)
		}
	}
	args := []string{"inventory"}
	for i := 0; i <= maxProjects; i++ {
		args = append(args, "--project", ".")
	}
	out.Reset()
	if code := Run(args, &out, &stderr); code != 1 || out.Len() != 0 {
		t.Fatal("project limit silently truncates")
	}
}
