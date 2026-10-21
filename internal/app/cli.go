package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/cowsecurity/emudhraslop/internal/cache"
	"github.com/cowsecurity/emudhraslop/internal/config"
	"github.com/cowsecurity/emudhraslop/internal/discovery"
	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/probe"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type flags struct {
	json, agent, online, offline, cached, allowRoot, noCache bool
	services, cache, scope, incident                         string
	projects                                                 projectPaths
	timeout, probeTimeout, maxAge                            time.Duration
	jobs                                                     int
}

func parse(args []string, stderr io.Writer) (string, flags, error) {
	var f flags
	if len(args) == 0 {
		return "", f, errors.New("expected inventory, check, or version")
	}
	command := args[0]
	if (command == "version" || command == "--version") && len(args) == 1 {
		command = "version"
		return command, f, nil
	}
	if command != "check" && command != "inventory" {
		return command, f, errors.New("expected inventory, check, or version")
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	// flag errors may contain attacker-controlled arguments. Emit our static
	// diagnostic instead; help contains only the declared flag names/defaults.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		fmt.Fprintln(stderr, commandHelp(command))
		fs.SetOutput(stderr)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	fs.BoolVar(&f.json, "json", false, "emit versioned JSON")
	fs.BoolVar(&f.agent, "agent", false, "emit JSON without a report cache; never prompts (same as --json --no-cache)")
	fs.BoolVar(&f.online, "online", false, "contact fixed public test endpoints with each declared native client")
	fs.BoolVar(&f.offline, "offline", false, "check local trust without network (default)")
	fs.BoolVar(&f.noCache, "no-cache", false, "emit report without reading or writing a report cache")
	fs.BoolVar(&f.cached, "cached", false, "validate a previous result without executing client probes")
	fs.BoolVar(&f.allowRoot, "allow-root-probes", false, "allow reviewed root-owned managed runtime execution as root")
	fs.StringVar(&f.services, "services", "", "strict JSON service manifest")
	fs.Var(&f.projects, "project", "include Python environments in this project directory (repeatable; no recursive search)")
	fs.StringVar(&f.cache, "cache", "", "opt in to saving a report at this path; also selects the --cached input")
	fs.StringVar(&f.scope, "scope", "managed", "managed runtime discovery")
	fs.StringVar(&f.incident, "incident", "emudhra-2026", "embedded incident ID")
	fs.DurationVar(&f.timeout, "timeout", 2*time.Minute, "total scan deadline")
	fs.DurationVar(&f.probeTimeout, "probe-timeout", 10*time.Second, "per native subprocess deadline")
	fs.DurationVar(&f.maxAge, "max-age", 24*time.Hour, "maximum cached report age")
	fs.IntVar(&f.jobs, "jobs", 2, "maximum simultaneous client contexts")
	if err := fs.Parse(args[1:]); err != nil {
		return command, f, err
	}
	if fs.NArg() != 0 {
		return command, f, errors.New("unexpected arguments")
	}
	if f.agent {
		f.json, f.noCache = true, true
	}
	if f.scope != "managed" || f.incident != "emudhra-2026" {
		return command, f, errors.New("unsupported scope or incident")
	}
	modes := 0
	for _, v := range []bool{f.online, f.offline, f.cached} {
		if v {
			modes++
		}
	}
	if f.noCache && (f.cached || f.cache != "") {
		return command, f, errors.New("--no-cache cannot be combined with cache options")
	}
	if len(f.projects) != 0 && f.services != "" {
		return command, f, errors.New("choose project discovery or a service manifest")
	}
	if modes > 1 {
		return command, f, errors.New("choose one of --online, --offline, --cached")
	}
	if f.jobs < 1 || f.jobs > 16 || f.timeout <= 0 || f.timeout > time.Hour || f.probeTimeout <= 0 || f.probeTimeout > time.Minute || f.maxAge <= 0 || f.maxAge > 7*24*time.Hour {
		return command, f, errors.New("resource limits outside supported bounds")
	}
	if command == "inventory" && (f.online || f.cached) {
		return command, f, errors.New("inventory does not run checks")
	}
	return command, f, nil
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "observation" {
		return RunObservation(args[1:], stdout, stderr)
	}
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")) {
		if _, err := fmt.Fprint(stdout, quickstart); err != nil {
			return 1
		}
		return 0
	}
	command, f, err := parse(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "emudhraslop: invalid arguments; use emudhraslop check --help")
		}
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if command == "version" {
		fmt.Fprintln(stdout, Version)
		return 0
	}
	in, err := incident.Load()
	if err != nil {
		fmt.Fprintln(stderr, "emudhraslop: embedded incident integrity validation failed")
		return 1
	}
	targets, coverage, err := loadProjectTargets(f.services, f.projects)
	if err != nil {
		fmt.Fprintln(stderr, "emudhraslop: service manifest or project directory cannot be read or is invalid")
		return 1
	}
	configuration, fpErr := config.Fingerprint(targets)
	if fpErr != nil {
		coverage.Complete = false
		coverage.Warnings = append(coverage.Warnings, "configuration_fingerprint_incomplete")
	}
	cachePath := f.cache
	if cachePath == "" && f.cached {
		if base, e := os.UserCacheDir(); e == nil {
			cachePath = filepath.Join(base, "emudhraslop", "report.json")
		}
	}
	mode := "offline"
	if f.online {
		mode = "online"
	}
	if command == "inventory" {
		mode = "inventory"
	}
	var report model.Report
	if f.cached {
		if fpErr == nil && cachePath != "" {
			report, err = cache.Load(cachePath, Version, in.SHA256, configuration, f.maxAge)
		} else {
			err = errors.New("cache context incomplete")
		}
		if err != nil {
			report = emptyReport(in, coverage, "cached")
			report.Errors = append(report.Errors, "cache_missing_stale_or_unverifiable")
			for _, target := range targets {
				result := model.NewResult(target)
				result.Reason = "cache_missing_stale_or_unverifiable"
				report.Results = append(report.Results, result)
			}
		}
		report.Mode = "cached"
	} else if command == "inventory" {
		report = emptyReport(in, coverage, mode)
		for _, t := range targets {
			r := model.NewResult(t)
			r.Reason = "inventory_only"
			r.NextAction = "Run check for this client context."
			report.Results = append(report.Results, r)
		}
	} else {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, deadline := context.WithTimeout(ctx, f.timeout)
		defer deadline()
		report = Scan(ctx, targets, coverage, in, ScanOptions{Probe: probe.Options{Online: f.online, ProbeTimeout: f.probeTimeout, AllowRoot: f.allowRoot, MaxOutput: 1024 * 1024}, Jobs: f.jobs, Mode: mode})
	}
	if !f.cached && command == "check" && fpErr == nil {
		after, afterErr := config.Fingerprint(targets)
		if afterErr != nil || after != configuration {
			report.Coverage.Complete = false
			report.Errors = append(report.Errors, "configuration_changed_during_scan")
			configuration = ""
			invalidateNegativeDecisions(&report, "configuration_changed_during_scan")
		}
	}
	report.Container = discovery.InContainer()
	report.ConfigurationSHA256 = configuration
	if fpErr != nil {
		report.Errors = append(report.Errors, "configuration_fingerprint_incomplete")
		invalidateNegativeDecisions(&report, "configuration_fingerprint_incomplete")
	}
	report.Status = Aggregate(report.Results, report.Coverage, len(report.Errors) > 0)
	stampDecisions(&report)
	if !f.cached && command == "check" && cachePath != "" {
		if err := cache.Save(cachePath, report); err != nil {
			report.Errors = append(report.Errors, "cache_write_failed")
			report.Status = Aggregate(report.Results, report.Coverage, true)
		}
	}
	stampDecisions(&report)
	if err := emit(stdout, report, f.json); err != nil {
		fmt.Fprintln(stderr, "emudhraslop: report output failed")
		return 1
	}
	return ExitCode(report.Status)
}

func loadTargets(path string) ([]model.Target, model.Coverage, error) {
	if path == "" {
		t, c := discovery.Managed()
		return t, c, nil
	}
	// Only the CLI accepts relative manifest paths. The Windows file boundary
	// still rejects UNC/device paths, indirect volumes and all reparse points.
	if runtime.GOOS == "windows" && !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, model.Coverage{}, err
		}
		path = absolute
	}
	t, err := config.Load(path)
	c := model.Coverage{Scope: "declared-clients", Complete: true, Exclusions: []string{"Running application behavior is not assessed; declared client settings are tested in isolation.", "Applications and client contexts absent from the service manifest are not assessed.", "Code signing, inbound server certificates and incident paths absent from the embedded manifest are not assessed."}, Warnings: []string{}}
	if runtime.GOOS == "windows" {
		c.Warnings = append(c.Warnings, "Windows checks use the current non-elevated token only; uid/gid 4294967295 is an unsupported Unix placeholder, not a Windows SID; report caching is unsupported; fresh checks do not use a cache")
	}
	for _, target := range t {
		if target.MetadataOnly {
			c.Complete = false
		}
	}
	return t, c, err
}

func emptyReport(in *incident.Incident, c model.Coverage, mode string) model.Report {
	return model.Report{SchemaVersion: model.SchemaVersion, AssessmentScope: "client_configurations", ApplicationStatus: model.Unknown, Version: Version, Incident: in.ID, ManifestVersion: in.Version, ManifestSHA256: in.SHA256, ScanTime: time.Now().UTC(), Status: model.Unknown, Mode: mode, Coverage: c, Results: []model.Result{}, Errors: []string{}}
}

// Null means the available evidence does not establish either answer.
func decision(status model.Status) *bool {
	switch status {
	case model.Affected:
		b := true
		return &b
	case model.NotAffected:
		b := false
		return &b
	default:
		return nil
	}
}
func stampDecisions(report *model.Report) {
	report.Affected = decision(report.Status)
	for i := range report.Results {
		report.Results[i].Affected = decision(report.Results[i].Status)
	}
}

func invalidateNegativeDecisions(report *model.Report, reason string) {
	for i := range report.Results {
		if report.Results[i].Status == model.NotAffected {
			report.Results[i].Status = model.Unknown
			report.Results[i].Affected = nil
			report.Results[i].Reason = reason
			report.Results[i].NextAction = "Rerun against a stable, fully fingerprinted executable and trust configuration."
		}
	}
}
