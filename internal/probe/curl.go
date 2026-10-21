package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

// Curl requires a verified successful connection AND the exact incident leaf.
// Network failures and a TLS-intercepting proxy's replacement leaf are unknown.
func Curl(ctx context.Context, t model.Target, inc *incident.Incident, opts Options) model.Result {
	r := model.NewResult(t)
	if t.VerificationDisabled {
		return nativeDisabled(r)
	}
	if err := validateRuntimeEnvironment(t.Environment, "curl"); err != nil {
		r.Reason = err.Error()
		return r
	}
	if !opts.Online {
		r.Reason = "curl_requires_online_native_probe"
		r.NextAction = "Run with --online to test this curl client."
		return r
	}
	version, err := run.Exec(ctx, t, []string{"--disable", "--version"}, nil, t.Environment, nativeRunOptions(opts))
	if err != nil {
		r.Reason = "native_execution_unavailable"
		return r
	}
	r.RuntimeVersion = nativeVersion(version.Stdout)
	for _, chain := range inc.Chains {
		check := model.Check{ChainID: chain.ID, Outcome: "unknown"}
		if !fixtureHost.MatchString(chain.Hostname) || !nativeFixtureValid(chain) {
			check.ErrorClass = "invalid_or_expired_fixture"
			r.Checks = append(r.Checks, check)
			continue
		}
		args := []string{"--disable", "--silent", "--proto", "=https", "--max-redirs", "0", "--connect-timeout", fmt.Sprintf("%.3f", opts.ProbeTimeout.Seconds()), "--max-time", fmt.Sprintf("%.3f", opts.ProbeTimeout.Seconds()), "--output", os.DevNull, "--write-out", "%{certs}"}
		if t.CABundle != "" {
			args = append(args, "--cacert", t.CABundle)
		}
		if t.CADir != "" {
			args = append(args, "--capath", t.CADir)
		}
		args = append(args, "--url", "https://"+chain.Hostname+"/")
		out, execErr := run.Exec(ctx, t, args, nil, t.Environment, nativeRunOptions(opts))
		if execErr != nil || out.ExitCode != 0 {
			check.ErrorClass = "native_rejection_or_network_failure"
		} else if !curlPinnedLeaf(out.Stdout, chain.LeafSHA256) {
			check.ErrorClass = "incident_leaf_not_observed"
		} else {
			check.Outcome = "accepted"
			check.Proof = "verified_native_curl_with_pinned_incident_leaf"
			r.Status = model.Affected
			r.Reason = "native_client_accepts_incident_chain"
		}
		r.Checks = append(r.Checks, check)
	}
	if r.Status == model.Affected {
		r.NextAction = "Update this curl client's trust configuration and rerun the check."
	} else {
		r.Reason = "native_rejections_not_attributed"
		r.NextAction = "Investigate proxy, network, certificate and client configuration before concluding protection."
	}
	return r
}

func curlPinnedLeaf(output []byte, want string) bool {
	// PEM decode only the first certificate; finding a pinned certificate later in
	// an unrelated chain cannot establish which peer the client authenticated.
	start := bytes.Index(output, []byte("-----BEGIN CERTIFICATE-----"))
	if start < 0 {
		return false
	}
	block, _ := pem.Decode(output[start:])
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}
	sum := sha256.Sum256(block.Bytes)
	return strings.EqualFold(hex.EncodeToString(sum[:]), want)
}
