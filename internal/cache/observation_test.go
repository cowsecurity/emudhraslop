//go:build !windows

package cache

import (
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func observationFixture(t *testing.T, status model.Status) (string, model.Report) {
	t.Helper()
	path, report := fixture(t)
	report.SchemaVersion = model.SchemaVersion
	report.AssessmentScope = "client_configurations"
	report.ApplicationStatus = model.Unknown
	report.Incident = "emudhra-2026"
	report.ManifestVersion = "test"
	report.Mode = "online"
	report.Coverage = model.Coverage{Scope: "declared-services", Complete: true, Exclusions: []string{}, Warnings: []string{}}
	report.Errors = []string{}
	report.Status = status
	report.Results = []model.Result{model.NewResult(model.Target{ID: "client", Kind: "node", Client: "tls", Source: "service-manifest"})}
	report.Results[0].Status = status
	report.Results[0].Reason = "test-fixture"
	if status != model.Unknown {
		affected := status == model.Affected
		report.Affected = &affected
		report.Results[0].Affected = &affected
	}
	return path, report
}

func TestObservationsPreserveHistoryWithoutCurrentConfirmation(t *testing.T) {
	for _, status := range []model.Status{model.Affected, model.NotAffected, model.Unknown} {
		t.Run(string(status), func(t *testing.T) {
			path, report := observationFixture(t, status)
			if err := Save(path, report); err != nil {
				t.Fatal(err)
			}
			got := Observe(path, report.Version, report.ManifestSHA256, time.Hour)
			if got.State != "fresh" || got.LastObservedStatus == nil || *got.LastObservedStatus != status || got.CurrentStatus != model.Unknown || got.ObservedAt == nil {
				t.Fatalf("lost or promoted observation: %#v", got)
			}
			// A new inspection does not require the old executable/trust file to exist:
			// this is explicitly historical, unlike Load's current-file validation.
			report.ScanTime = time.Now().Add(-2 * time.Hour)
			if err := Save(path, report); err != nil {
				t.Fatal(err)
			}
			got = Observe(path, report.Version, report.ManifestSHA256, time.Hour)
			if got.State != "stale" || got.LastObservedStatus == nil || *got.LastObservedStatus != status || got.CurrentStatus != model.Unknown {
				t.Fatalf("stale history: %#v", got)
			}
		})
	}
}

func TestObservationRejectsAmbiguousAndInconsistentReports(t *testing.T) {
	cases := map[string]func(*model.Report){
		"schema":                       func(r *model.Report) { r.SchemaVersion = 1 },
		"version":                      func(r *model.Report) { r.Version = "old" },
		"incident":                     func(r *model.Report) { r.Incident = "other" },
		"manifest":                     func(r *model.Report) { r.ManifestSHA256 = strings.Repeat("c", 64) },
		"future":                       func(r *model.Report) { r.ScanTime = time.Now().Add(time.Hour) },
		"application_confirmation":     func(r *model.Report) { r.ApplicationStatus = model.NotAffected },
		"missing_basis":                func(r *model.Report) { r.Results[0].AssessmentBasis = "" },
		"row_application_confirmation": func(r *model.Report) { r.Results[0].ApplicationStatus = model.Affected },
		"inventory":                    func(r *model.Report) { r.Mode = "inventory" },
		"hidden_positive":              func(r *model.Report) { r.Status = model.Unknown; r.Affected = nil },
		"boolean_mismatch":             func(r *model.Report) { b := false; r.Affected = &b },
		"row_boolean_mismatch":         func(r *model.Report) { r.Results[0].Affected = nil },
		"duplicate_id":                 func(r *model.Report) { r.Results = append(r.Results, r.Results[0]) },
		"empty_id":                     func(r *model.Report) { r.Results[0].ID = "" },
		"invalid_status":               func(r *model.Report) { r.Results[0].Status = "safe" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			path, r := observationFixture(t, model.Affected)
			version, hash := r.Version, r.ManifestSHA256
			mutate(&r)
			if err := Save(path, r); err != nil {
				t.Fatal(err)
			}
			got := Observe(path, version, hash, time.Hour)
			if got.State != "invalid" || got.LastObservedStatus != nil || got.ObservedAt != nil || got.CurrentStatus != model.Unknown {
				t.Fatalf("accepted invalid observation: %#v", got)
			}
		})
	}
}

func TestObservationJSONAndFileBoundaryAttacks(t *testing.T) {
	for _, attack := range []string{"duplicate", "case_folded", "missing_boolean", "unknown_field", "trailing", "public", "symlink", "hardlink", "fifo", "oversized"} {
		t.Run(attack, func(t *testing.T) {
			path, r := observationFixture(t, model.Affected)
			if err := Save(path, r); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "duplicate":
				data = append([]byte(`{"status":"unknown",`), data[1:]...)
			case "case_folded":
				data = []byte(strings.Replace(string(data), `"status":`, `"STATUS":`, 1))
			case "missing_boolean":
				var object map[string]any
				if err := json.Unmarshal(data, &object); err != nil {
					t.Fatal(err)
				}
				delete(object, "affected")
				data, _ = json.Marshal(object)
			case "unknown_field":
				data = append([]byte(`{"unexpected":true,`), data[1:]...)
			case "trailing":
				data = append(data, []byte(" {}")...)
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".real", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				data = make([]byte, maxReportBytes+1)
			}
			switch attack {
			case "public", "symlink", "hardlink", "fifo":
			default:
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got := Observe(path, r.Version, r.ManifestSHA256, time.Hour)
			if got.State != "invalid" || got.LastObservedStatus != nil {
				t.Fatalf("accepted %s: %#v", attack, got)
			}
		})
	}
}

func TestObservationCannotHideIncompleteNegativeScope(t *testing.T) {
	for name, mutate := range map[string]func(*model.Report){
		"incomplete":      func(r *model.Report) { r.Coverage.Complete = false },
		"report_error":    func(r *model.Report) { r.Errors = []string{"scan_failed"} },
		"empty_scope":     func(r *model.Report) { r.Results = nil },
		"unknown_context": func(r *model.Report) { r.Results[0].Status = model.Unknown; r.Results[0].Affected = nil },
	} {
		t.Run(name, func(t *testing.T) {
			path, r := observationFixture(t, model.NotAffected)
			mutate(&r)
			if err := Save(path, r); err != nil {
				t.Fatal(err)
			}
			if got := Observe(path, r.Version, r.ManifestSHA256, time.Hour); got.State != "invalid" {
				t.Fatalf("accepted inconsistent negative: %#v", got)
			}
		})
	}
}
