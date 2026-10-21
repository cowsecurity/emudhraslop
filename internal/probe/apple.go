package probe

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"runtime"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

//go:embed apple_helper.swift
var appleHelper []byte

type appleInput struct {
	ID           string   `json:"id"`
	Hostname     string   `json:"hostname"`
	Certificates []string `json:"certificates"`
}
type appleCheck struct {
	ID       string `json:"id"`
	Accepted bool   `json:"accepted"`
	Error    int    `json:"error"`
}
type appleOutput struct {
	Version string       `json:"version"`
	Checks  []appleCheck `json:"checks"`
}

// Apple evaluates public incident fixtures through native SecTrust, without
// consulting the scanner's Go certificate verifier or fetching issuer data.
func Apple(ctx context.Context, t model.Target, inc *incident.Incident, opts Options) model.Result {
	r := model.NewResult(t)
	if t.VerificationDisabled {
		return nativeDisabled(r)
	}
	if runtime.GOOS != "darwin" {
		r.Reason = "apple_trust_unavailable_on_platform"
		return r
	}
	if t.CABundle != "" || t.CADir != "" || len(t.Environment) > 0 {
		r.Reason = "apple_custom_trust_context_unsupported"
		return r
	}
	dir, cleanup, err := nativeTemp(t)
	if err != nil {
		r.Reason = "fixture_directory_unavailable"
		return r
	}
	defer cleanup()
	script := filepath.Join(dir, "probe.swift")
	if nativeWrite(t, script, appleHelper) != nil {
		r.Reason = "native_helper_unavailable"
		return r
	}
	cache := filepath.Join(dir, "modules")
	if t.Client != "sectrust-helper" && nativeCache(t, cache) != nil {
		r.Reason = "native_helper_cache_unavailable"
		return r
	}
	inputs := make([]appleInput, 0, len(inc.Chains))
	for _, chain := range inc.Chains {
		if !nativeFixtureValid(chain) {
			r.Checks = append(r.Checks, model.Check{ChainID: chain.ID, Outcome: "unknown", ErrorClass: "invalid_or_expired_fixture"})
			continue
		}
		item := appleInput{ID: chain.ID, Hostname: chain.Hostname}
		for _, cert := range chain.Certificates {
			item.Certificates = append(item.Certificates, base64.StdEncoding.EncodeToString(cert.Raw))
		}
		inputs = append(inputs, item)
	}
	if len(inputs) == 0 {
		r.Reason = "no_valid_incident_fixtures"
		return r
	}
	input, _ := json.Marshal(inputs)
	args := []string{"-module-cache-path", cache, script}
	if t.Client == "sectrust-helper" {
		args = nil
	}
	out, err := run.Exec(ctx, t, args, input, nil, nativeRunOptions(opts))
	if err != nil {
		r.Reason = "sectrust_helper_unavailable_or_timed_out"
		r.NextAction = "Install managed Apple command line tools, or run a packaged native helper as the service user."
		return r
	}
	var decoded appleOutput
	if json.Unmarshal(out.Stdout, &decoded) != nil || len(decoded.Checks) != len(inputs) {
		r.Reason = "sectrust_helper_response_invalid"
		return r
	}
	seen := make(map[string]bool, len(inputs))
	expected := make(map[string]bool, len(inputs))
	for _, input := range inputs {
		expected[input.ID] = true
	}
	for _, check := range decoded.Checks {
		if !expected[check.ID] || seen[check.ID] {
			r.Reason = "sectrust_helper_response_invalid"
			return r
		}
		seen[check.ID] = true
	}
	r.RuntimeVersion = nativeVersion([]byte(decoded.Version))
	for _, check := range decoded.Checks {
		item := model.Check{ChainID: check.ID, Outcome: "unknown", ErrorClass: "native_rejection_not_attributed"}
		if check.Accepted {
			item.Outcome = "accepted"
			item.Proof = "native_sectrust_ssl_policy_fixture_verification"
			item.ErrorClass = ""
			r.Status = model.Affected
			r.Reason = "native_client_accepts_incident_chain"
		}
		r.Checks = append(r.Checks, item)
	}
	if r.Status == model.Affected {
		r.NextAction = "Update Apple trust policy for this execution identity and rerun the check."
	} else {
		r.Reason = "native_rejections_not_attributed"
		r.NextAction = "Confirm the native distrust reason and effective system/user trust policy before concluding protection."
	}
	return r
}
