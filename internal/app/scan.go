package app

import (
	"context"
	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/probe"
	"sync"
	"time"
)

var Version = "0.1.0-dev"

type ScanOptions struct {
	Probe probe.Options
	Jobs  int
	Mode  string
}

func Scan(ctx context.Context, targets []model.Target, coverage model.Coverage, in *incident.Incident, opts ScanOptions) model.Report {
	report := model.Report{SchemaVersion: 1, Version: Version, Incident: in.ID, ManifestVersion: in.Version, ManifestSHA256: in.SHA256, ScanTime: time.Now().UTC(), Mode: opts.Mode, Coverage: coverage, Results: make([]model.Result, len(targets)), Errors: []string{}}
	if err := in.Validate(report.ScanTime); err != nil {
		report.Errors = append(report.Errors, "fixture_validation_failed")
		report.Coverage.Complete = false
		for i, t := range targets {
			report.Results[i] = model.NewResult(t)
			report.Results[i].Reason = "fixture_validation_failed"
			if t.VerificationDisabled {
				report.Results[i] = probe.Check(ctx, t, in, opts.Probe)
			}
		}
		report.Status = Aggregate(report.Results, report.Coverage, true)
		return report
	}
	jobs := opts.Jobs
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(targets) {
		jobs = len(targets)
	}
	indices := make(chan int)
	var wg sync.WaitGroup
	for j := 0; j < jobs; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indices {
				report.Results[i] = probe.Check(ctx, targets[i], in, opts.Probe)
			}
		}()
	}
	for i := range targets {
		indices <- i
	}
	close(indices)
	wg.Wait()
	report.Status = Aggregate(report.Results, report.Coverage, len(report.Errors) > 0)
	return report
}

func Aggregate(results []model.Result, coverage model.Coverage, hasErrors bool) model.Status {
	status := model.NotAffected
	if len(results) == 0 || !coverage.Complete || hasErrors {
		status = model.Unknown
	}
	for _, r := range results {
		if r.Status == model.Affected {
			return model.Affected
		}
		if r.Status != model.NotAffected {
			status = model.Unknown
		}
	}
	return status
}

func ExitCode(status model.Status) int {
	switch status {
	case model.NotAffected:
		return 0
	case model.Affected:
		return 2
	default:
		return 3
	}
}
