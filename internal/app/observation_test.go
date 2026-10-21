//go:build !windows

package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/cache"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

func TestObservationCommandReadsActualStoredScan(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "services.json")
	data, err := json.Marshal(map[string]any{"schema_version": 1, "services": []model.Target{{ID: "disabled", Kind: "node", Executable: executable, Environment: map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "report.json")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"check", "--offline", "--services", manifest, "--cache", path, "--json"}, &stdout, &stderr)
	var report model.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if code != 2 || report.Status != model.Affected || len(report.Errors) != 0 {
		t.Fatalf("fresh scan %d %s %s", code, stdout.String(), stderr.String())
	}
	// Exercise the actual CLI dispatch, not just the observation helper.
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"observation", "--cache", path}, &stdout, &stderr); code != 0 || stdout.String() != "observed_affected\n" {
		t.Fatalf("observation %d %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := Run([]string{"observation", "--cache", path, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatal(code)
	}
	var observed cache.Observation
	if err := json.Unmarshal(stdout.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.CurrentStatus != model.Unknown || observed.LastObservedStatus == nil || *observed.LastObservedStatus != model.Affected {
		t.Fatalf("observation claims current assessment: %#v", observed)
	}
	report.ScanTime = time.Now().Add(-48 * time.Hour)
	if err := cache.Save(path, report); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := Run([]string{"observation", "--cache", path}, &stdout, &stderr); code != 3 || stdout.String() != "unknown\n" {
		t.Fatalf("stale %d %q", code, stdout.String())
	}
	stdout.Reset()
	if code := Run([]string{"observation", "--cache", path, "--json"}, &stdout, &stderr); code != 3 {
		t.Fatal(code)
	}
	if err := json.Unmarshal(stdout.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.State != "stale" || observed.LastObservedStatus == nil || *observed.LastObservedStatus != model.Affected {
		t.Fatalf("lost stale history %#v", observed)
	}
}

func TestObservationInvalidArgumentsDoNotEchoUntrustedInput(t *testing.T) {
	for _, args := range [][]string{{}, {"--cache", "/missing", "--max-age", "-1s"}, {"--cache", "/missing", "--max-age", "169h"}, {"--cache", "/missing", "--unexpected=secret"}, {"--cache", "/missing", "extra-secret"}} {
		var stdout, stderr bytes.Buffer
		if code := RunObservation(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || strings.Contains(stderr.String(), "secret") {
			t.Fatalf("unsafe diagnostic %d %q %q", code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := RunObservation([]string{"--cache", "/missing"}, &stdout, &stderr); code != 3 || stdout.String() != "unknown\n" || stderr.Len() != 0 {
		t.Fatalf("invalid report %d %q %q", code, stdout.String(), stderr.String())
	}
}
