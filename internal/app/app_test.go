package app

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/probe"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAggregatePreservesUnknownAndAffected(t *testing.T) {
	complete := model.Coverage{Complete: true}
	cases := []struct {
		results  []model.Result
		coverage model.Coverage
		errors   bool
		want     model.Status
	}{
		{nil, complete, false, model.Unknown},
		{[]model.Result{{Status: model.NotAffected}}, complete, false, model.NotAffected},
		{[]model.Result{{Status: model.NotAffected}}, model.Coverage{}, false, model.Unknown},
		{[]model.Result{{Status: model.NotAffected}}, complete, true, model.Unknown},
		{[]model.Result{{Status: model.Unknown}, {Status: model.Affected}}, model.Coverage{}, true, model.Affected},
		{[]model.Result{{Status: model.NotAffected}, {Status: model.Unknown}}, complete, false, model.Unknown},
		{[]model.Result{{Status: "unexpected"}}, complete, false, model.Unknown},
	}
	for _, tc := range cases {
		if got := Aggregate(tc.results, tc.coverage, tc.errors); got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
}

func TestDeclaredDisabledTLSIsAffectedWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "services.json")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(map[string]any{"schema_version": 1, "services": []model.Target{{ID: "disabled-client", Kind: "node", Executable: executable, Environment: map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"}}}})
	if err != nil {
		t.Fatal(err)
	}
	data := string(encoded)
	if err := os.WriteFile(manifest, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := Run([]string{"check", "--offline", "--services", manifest, "--cache", filepath.Join(dir, "report.json"), "--json"}, &out, &stderr)
	if code != 2 {
		t.Fatalf("exit=%d stderr=%s output=%s", code, stderr.String(), out.String())
	}
	var report model.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != model.Affected || len(report.Results) != 1 || report.Results[0].Reason != "tls_verification_disabled" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if bytes.Contains(out.Bytes(), []byte("NODE_TLS_REJECT_UNAUTHORIZED")) {
		t.Fatal("environment leaked")
	}
}

func TestNoExecutableInEmptyContainerIsUnknown(t *testing.T) {
	in, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	report := Scan(context.Background(), nil, model.Coverage{Scope: "declared-services", Complete: true}, in, ScanOptions{Jobs: 2, Mode: "offline"})
	if report.Status != model.Unknown || ExitCode(report.Status) != 3 {
		t.Fatal("empty scope treated as protected")
	}
}

func TestCancelledScanKeepsEveryTarget(t *testing.T) {
	in, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	targets := []model.Target{{ID: "one", Kind: "python"}, {ID: "two", Kind: "node"}, {ID: "three", Kind: "curl"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := Scan(ctx, targets, model.Coverage{Complete: true}, in, ScanOptions{Jobs: 2, Probe: probe.Options{ProbeTimeout: time.Second, MaxOutput: 1024}})
	if len(report.Results) != len(targets) {
		t.Fatal("target silently dropped")
	}
	for i, r := range report.Results {
		if r.ID != targets[i].ID || r.Status != model.Unknown {
			t.Fatal("cancelled target misclassified")
		}
	}
}

func TestInvalidCacheStillEmitsUnknownJSON(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "services.json")
	if err := os.WriteFile(manifest, []byte(`{"schema_version":1,"services":[{"id":"custom","kind":"java"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := Run([]string{"check", "--cached", "--services", manifest, "--cache", filepath.Join(dir, "missing.json"), "--json"}, &out, &stderr)
	if code != 3 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report model.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != model.Unknown || len(report.Errors) == 0 {
		t.Fatal("missing cache not visible")
	}
}

func TestBadCLIInputsRejectedBeforeWork(t *testing.T) {
	cases := [][]string{{"check", "--online", "--offline"}, {"check", "--jobs", "0"}, {"check", "--jobs", "17"}, {"check", "--timeout", "0s"}, {"check", "--probe-timeout", "2m"}, {"check", "--max-age", "1000h"}, {"inventory", "--online"}, {"check", "extra"}, {"check", "--incident", "unknown"}}
	for _, args := range cases {
		var out, stderr bytes.Buffer
		if code := Run(args, &out, &stderr); code != 1 || out.Len() != 0 {
			t.Fatalf("accepted bad arguments %v", args)
		}
	}
}

func TestAgentDecisionBooleanAndNoCache(t *testing.T) {
	for _, tc := range []struct {
		status model.Status
		want   *bool
	}{{model.Affected, decision(model.Affected)}, {model.NotAffected, decision(model.NotAffected)}, {model.Unknown, nil}} {
		report := model.Report{Status: tc.status, Results: []model.Result{{Status: tc.status}}}
		stampDecisions(&report)
		if tc.want == nil {
			if report.Affected != nil || report.Results[0].Affected != nil {
				t.Fatal("inconclusive decision became false")
			}
		} else if report.Affected == nil || *report.Affected != *tc.want || *report.Results[0].Affected != *tc.want {
			t.Fatal("decision disagrees with status")
		}
	}
	dir := t.TempDir()
	manifest := filepath.Join(dir, "services.json")
	if err := os.WriteFile(manifest, []byte(`{"schema_version":1,"services":[{"id":"custom","kind":"java"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := Run([]string{"check", "--services", manifest, "--no-cache", "--json"}, &out, &stderr); code != 3 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report model.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Affected != nil || len(report.Errors) != 0 {
		t.Fatalf("unexpected no-cache report %+v", report)
	}
}

func TestExpiredFixturesDoNotEraseDeclaredDisabledVerification(t *testing.T) {
	in, err := incident.Load()
	if err != nil {
		t.Fatal(err)
	}
	in.Chains[0].Certificates[0].NotAfter = time.Now().Add(-time.Hour)
	targets := []model.Target{{ID: "disabled-custom", Kind: "custom", MetadataOnly: true, VerificationDisabled: true}, {ID: "unverified", Kind: "python"}}
	report := Scan(context.Background(), targets, model.Coverage{Complete: true}, in, ScanOptions{})
	if report.Status != model.Affected || report.Results[0].Status != model.Affected || report.Results[1].Status != model.Unknown || len(report.Errors) == 0 {
		t.Fatalf("known disabled verification disappeared: %+v", report)
	}
}

func TestDetectedConfigurationDriftInvalidatesEveryNegativeRow(t *testing.T) {
	report := model.Report{Status: model.NotAffected, Results: []model.Result{{ID: "negative", Status: model.NotAffected}, {ID: "positive", Status: model.Affected}, {ID: "incomplete", Status: model.Unknown}}}
	stampDecisions(&report)
	invalidateNegativeDecisions(&report, "configuration_changed_during_scan")
	report.Status = Aggregate(report.Results, model.Coverage{Complete: false}, true)
	stampDecisions(&report)
	if report.Results[0].Status != model.Unknown || report.Results[0].Affected != nil || report.Results[0].Reason != "configuration_changed_during_scan" {
		t.Fatal("stale per-context negative retained")
	}
	if report.Results[1].Status != model.Affected || report.Results[1].Affected == nil || !*report.Results[1].Affected || report.Status != model.Affected {
		t.Fatal("observed exposure silently erased")
	}
	if report.Results[2].Status != model.Unknown || report.Results[2].Affected != nil {
		t.Fatal("incomplete evidence coerced to false")
	}
}
