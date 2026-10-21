package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

type runtimeInput struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Client   string  `json:"client"`
	Timeout  float64 `json:"timeout"`
	CABundle string  `json:"ca_bundle"`
	CADir    string  `json:"ca_dir"`
}

type runtimeObservation struct {
	Version    string              `json:"version"`
	Accepted   bool                `json:"accepted"`
	LeafSHA256 string              `json:"leaf_sha256"`
	ErrorClass string              `json:"error_class"`
	Sources    []model.TrustSource `json:"sources"`
}

var runtimeHash = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var fixtureHost = regexp.MustCompile(`^(dv|ov|ev)-g3[bc](-aaa)?-emudhra\.we-have-a-problem\.com$`)

// Runtime environment is deliberately narrow: hooks can execute arbitrary code,
// while credential-bearing proxies could disclose secrets to the test network.
func validateRuntimeEnvironment(environment map[string]string, kind string) error {
	for key, value := range environment {
		if !run.AllowedEnvironment(key) || strings.ContainsAny(value, "\x00\n\r") {
			return errors.New("unsupported_environment")
		}
		if strings.Contains(strings.ToLower(key), "proxy") && !strings.EqualFold(key, "no_proxy") && value != "" {
			u, err := url.Parse(value)
			if err != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
				return errors.New("unsupported_proxy_configuration")
			}
		}
		if key == "NODE_TLS_REJECT_UNAUTHORIZED" && value != "1" && value != "" {
			return errors.New("verification_disabled")
		}
		if key == "NODE_OPTIONS" {
			if err := run.ValidateNodeOptions(value); err != nil {
				return errors.New("unsupported_node_options")
			}
		}
		if kind == "node" && strings.Contains(strings.ToLower(key), "proxy") && value != "" {
			return errors.New("unsupported_proxy_configuration")
		}
	}
	return nil
}

func runtimeExecute(ctx context.Context, t model.Target, input runtimeInput, script string, args []string, opts Options) (runtimeObservation, error) {
	var observation runtimeObservation
	data, err := json.Marshal(input)
	if err != nil {
		return observation, err
	}
	output, err := run.Exec(ctx, t, append(args, script), data, t.Environment, run.Options{Timeout: opts.ProbeTimeout, MaxOutput: opts.MaxOutput, AllowRoot: opts.AllowRoot})
	if err != nil {
		return observation, err
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Stdout))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&observation); err != nil {
		return observation, errors.New("invalid_probe_response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return observation, errors.New("invalid_probe_response")
	}
	if len(observation.Version) > 100 || strings.ContainsAny(observation.Version, "\n\r\x00") || len(observation.Sources) > 16 {
		return runtimeObservation{}, errors.New("invalid_probe_response")
	}
	for _, source := range observation.Sources {
		if len(source.Path) > 4096 || (source.SHA256 != "" && !runtimeHash.MatchString(source.SHA256)) {
			return runtimeObservation{}, errors.New("invalid_probe_response")
		}
	}
	return observation, nil
}

func runtimeProbe(ctx context.Context, t model.Target, inc *incident.Incident, opts Options, script string, args []string) model.Result {
	r := model.NewResult(t)
	r.NextAction = "Run an online native check; application-specific TLS settings require a separate declared context."
	if err := validateRuntimeEnvironment(t.Environment, t.Kind); err != nil {
		r.Reason = err.Error()
		return r
	}
	if t.VerificationDisabled {
		r.Reason = "verification_disabled"
		return r
	}
	// Even -I -S imports Python's startup modules. A trusted executable path
	// does not attest pyvenv.cfg, its selected stdlib, or other startup files.
	// Root opt-in therefore cannot authorize any Python interpreter execution.
	if t.Kind == "python" && os.Geteuid() == 0 && (t.UID == nil || *t.UID == 0 || t.GID == nil || *t.GID == 0) {
		r.Reason = "root_python_execution_denied"
		r.NextAction = "Run Python probes as an explicit non-root service uid/gid."
		return r
	}
	if t.Kind == "python" && (t.Client == "stdlib" || t.Client == "botocore") {
		for key, value := range t.Environment {
			if strings.Contains(strings.ToLower(key), "proxy") && value != "" {
				r.Reason = "unsupported_proxy_configuration"
				return r
			}
		}
	}
	input := runtimeInput{Host: "www.google.com", Port: 443, Client: t.Client, Timeout: opts.ProbeTimeout.Seconds(), CABundle: t.CABundle, CADir: t.CADir}
	if !opts.Online {
		input.Host = ""
	}
	control, err := runtimeExecute(ctx, t, input, script, args, opts)
	if err != nil {
		r.Reason = safeRuntimeExecError(err)
		return r
	}
	r.RuntimeVersion, r.TrustSources = control.Version, control.Sources
	// An unavailable adapter cannot make any incident-chain request. Keep the
	// context visible as unknown without repeating the same failed import for
	// every chain. Network/control failures still proceed to incident probes.
	switch control.ErrorClass {
	case "package_unavailable", "unsupported_client", "unsupported_configuration", "trust_source_unreadable":
		r.Reason = control.ErrorClass
		r.NextAction = "Select the application's actual installed client and readable trust settings; the scanner does not install packages."
		return r
	}
	if !opts.Online {
		r.Reason = "offline_native_policy_not_proven"
		return r
	}
	r.ControlOK = control.Accepted && runtimeHash.MatchString(control.LeafSHA256)
	if !r.ControlOK {
		r.Reason = "clean_control_failed"
	} else {
		r.Reason = "native_rejections_do_not_prove_protection"
	}
	for _, chain := range inc.Chains {
		check := model.Check{ChainID: chain.ID, Outcome: "unknown"}
		if !fixtureHost.MatchString(chain.Hostname) || !runtimeHash.MatchString(chain.LeafSHA256) {
			check.ErrorClass = "invalid_fixture_identity"
			r.Checks = append(r.Checks, check)
			continue
		}
		if ctx.Err() != nil {
			check.ErrorClass = "scan_cancelled"
			r.Checks = append(r.Checks, check)
			continue
		}
		input.Host = chain.Hostname
		observed, err := runtimeExecute(ctx, t, input, script, args, opts)
		if err != nil {
			check.ErrorClass = safeRuntimeExecError(err)
		} else if observed.Accepted {
			if runtimePinnedAcceptance(observed, chain.LeafSHA256) {
				check.Outcome = "accepted"
				check.Proof = "native_validation_and_pinned_leaf"
				r.Status = model.Affected
				r.Reason = "native_client_accepted_incident_fixture"
				r.NextAction = "Update this runtime and effective trust configuration, then rerun its native check."
			} else {
				check.ErrorClass = "peer_identity_mismatch"
			}
		} else {
			check.Outcome = "rejected_or_unreachable"
			check.ErrorClass = safeRuntimeError(observed.ErrorClass)
		}
		r.Checks = append(r.Checks, check)
	}
	return r
}

func runtimePinnedAcceptance(observed runtimeObservation, expected string) bool {
	return observed.Accepted && runtimeHash.MatchString(expected) && runtimeHash.MatchString(observed.LeafSHA256) && strings.EqualFold(observed.LeafSHA256, expected)
}

func safeRuntimeExecError(err error) string {
	switch {
	case errors.Is(err, run.ErrRootDenied):
		return "root_probe_denied"
	case errors.Is(err, run.ErrOutputLimit):
		return "probe_output_limit"
	case errors.Is(err, context.DeadlineExceeded):
		return "probe_timeout"
	case errors.Is(err, context.Canceled):
		return "scan_cancelled"
	default:
		return "runtime_probe_failed"
	}
}

func safeRuntimeError(class string) string {
	switch class {
	case "certificate_rejected", "timeout", "network_error", "package_unavailable", "peer_certificate_unavailable", "unsupported_client", "unsupported_configuration", "trust_source_unreadable":
		return class
	}
	return "native_error"
}
