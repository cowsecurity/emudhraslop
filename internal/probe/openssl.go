package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

// OpenSSL tests an explicitly selected OpenSSL trust context. Its outcome never
// stands in for Python, curl, or another application's TLS configuration.
func OpenSSL(ctx context.Context, t model.Target, inc *incident.Incident, opts Options) model.Result {
	r := model.NewResult(t)
	if t.VerificationDisabled {
		return nativeDisabled(r)
	}
	if err := validateRuntimeEnvironment(t.Environment, "openssl"); err != nil {
		r.Reason = err.Error()
		return r
	}
	if t.CABundle == "" && t.CADir == "" {
		r.Reason = "openssl_explicit_trust_context_required"
		r.NextAction = "Declare the OpenSSL CA bundle or directory used by this service."
		return r
	}
	dir, cleanup, err := nativeTemp(t)
	if err != nil {
		r.Reason = "fixture_directory_unavailable"
		return r
	}
	defer cleanup()
	version, err := run.Exec(ctx, t, []string{"version"}, nil, t.Environment, nativeRunOptions(opts))
	if err != nil {
		r.Reason = "native_execution_unavailable"
		return r
	}
	r.RuntimeVersion = nativeVersion(version.Stdout)
	// A negative conclusion is possible only for one complete, immutable CA-file
	// context. Other OpenSSL variants and mixed/default stores stay conservative.
	bundlePath := t.CABundle
	var bundle []byte
	var control *x509.Certificate
	exclusiveSupported := strings.HasPrefix(r.RuntimeVersion, "OpenSSL 3.") && t.CABundle != "" && t.CADir == "" && len(t.Environment) == 0
	if t.ExclusiveCABundle && !exclusiveSupported {
		r.Reason = "unsupported_exclusive_ca_bundle_context"
		r.NextAction = "Use an OpenSSL 3 context with one CA file and no extra trust stores or environment overrides."
		return r
	}
	isolated := t.ExclusiveCABundle && exclusiveSupported
	negativeEligible := false
	if isolated {
		var certs []*x509.Certificate
		bundle, certs, err = opensslReadBundle(t.CABundle)
		if err != nil {
			r.Reason = "explicit_ca_bundle_incomplete"
			return r
		}
		bundlePath = filepath.Join(dir, "ca-snapshot.pem")
		if nativeWrite(t, bundlePath, bundle) != nil {
			r.Reason = "fixture_write_failed"
			return r
		}
		r.TrustSources = []model.TrustSource{{Path: t.CABundle, SHA256: incident.Hash(bundle), Complete: true}}
		control, negativeEligible = opensslNegativePolicy(inc, certs)
	}
	allIssuerRejections := negativeEligible
	for index, chain := range inc.Chains {
		check := model.Check{ChainID: chain.ID, Outcome: "unknown"}
		if !nativeFixtureValid(chain) {
			allIssuerRejections = false
			check.ErrorClass = "invalid_or_expired_fixture"
			r.Checks = append(r.Checks, check)
			continue
		}
		leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.Certificates[0].Raw})
		var intermediates []byte
		for _, cert := range chain.Certificates[1:] {
			intermediates = append(intermediates, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
		leafPath, chainPath := filepath.Join(dir, fmt.Sprintf("leaf-%d.pem", index)), filepath.Join(dir, fmt.Sprintf("chain-%d.pem", index))
		if nativeWrite(t, leafPath, leaf) != nil || nativeWrite(t, chainPath, intermediates) != nil {
			allIssuerRejections = false
			check.ErrorClass = "fixture_write_failed"
			r.Checks = append(r.Checks, check)
			continue
		}
		args := []string{"verify", "-purpose", "sslserver"}
		if isolated {
			args = append(args, "-verify_hostname", chain.Hostname, "-no-CApath", "-no-CAstore")
		}
		if t.CABundle != "" {
			args = append(args, "-CAfile", bundlePath)
		}
		if t.CADir != "" {
			args = append(args, "-CApath", t.CADir)
		}
		args = append(args, "-untrusted", chainPath, leafPath)
		out, execErr := run.Exec(ctx, t, args, nil, t.Environment, nativeRunOptions(opts))
		if execErr == nil && out.ExitCode == 0 && nativeDropsIdentity(t) && bundlePath != t.CABundle {
			// A root reader must not grant the service access to a trust file it
			// cannot open. Confirm acceptance using the service's original path.
			for i := 0; i+1 < len(args); i++ {
				if args[i] == "-CAfile" {
					args[i+1] = t.CABundle
					break
				}
			}
			out, execErr = run.Exec(ctx, t, args, nil, t.Environment, nativeRunOptions(opts))
		}
		if execErr == nil && out.ExitCode == 0 && strings.Contains(string(out.Stdout), leafPath+": OK") {
			allIssuerRejections = false
			check.Outcome = "accepted"
			check.Proof = "native_openssl_fixture_verification"
			r.Status = model.Affected
			r.Reason = "native_client_accepts_incident_chain"
		} else if negativeEligible && opensslIssuerRejection(out, execErr, leafPath) {
			check.Outcome = "rejected"
			check.Proof = "native_openssl_explicit_bundle_issuer_absent"
		} else {
			allIssuerRejections = false
			check.ErrorClass = "native_rejection_or_execution_failure"
		}
		r.Checks = append(r.Checks, check)
	}
	if isolated {
		current, _, readErr := opensslReadBundle(t.CABundle)
		if readErr != nil || !bytes.Equal(bundle, current) {
			r.Status = model.Unknown
			r.Reason = "trust_policy_changed_during_probe"
			r.NextAction = "Rerun with a stable CA file."
			return r
		}
	}
	if r.Status == model.Affected {
		r.NextAction = "Update this client's trust configuration and rerun the check."
	} else if allIssuerRejections && control != nil {
		controlPath := filepath.Join(dir, "control.pem")
		if nativeWrite(t, controlPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: control.Raw})) == nil {
			// Use the original path for the control, so a privileged parent cannot
			// manufacture a readable service context by copying an inaccessible CA.
			// A root CA is not a TLS server leaf. This control proves native trust
			// loading/signature verification; incident probes keep sslserver purpose.
			args := []string{"verify", "-purpose", "any", "-check_ss_sig", "-no-CApath", "-no-CAstore", "-CAfile", t.CABundle, controlPath}
			out, err := run.Exec(ctx, t, args, nil, nil, nativeRunOptions(opts))
			r.ControlOK = err == nil && out.ExitCode == 0 && strings.TrimSpace(string(out.Stdout)) == controlPath+": OK"
		}
		current, _, readErr := opensslReadBundle(t.CABundle)
		if r.ControlOK && readErr == nil && bytes.Equal(bundle, current) {
			r.Status = model.NotAffected
			r.Reason = "known_incident_tls_paths_not_trusted_by_explicit_openssl_bundle"
			r.NextAction = "No remediation is indicated for this explicit OpenSSL CA-file context; assess other service contexts separately."
			return r
		}
		r.Reason = "negative_proof_control_or_policy_stability_failed"
		r.NextAction = "Rerun with a stable complete CA file and a working native verifier."
	} else {
		r.Reason = "native_rejections_not_attributed"
		r.NextAction = "Investigate native rejection reasons; rejection alone does not prove protection."
	}
	return r
}

func nativeRunOptions(opts Options) run.Options {
	return run.Options{Timeout: opts.ProbeTimeout, MaxOutput: opts.MaxOutput, AllowRoot: opts.AllowRoot}
}
func nativeDisabled(r model.Result) model.Result {
	r.Status = model.Affected
	r.Reason = "tls_verification_explicitly_disabled"
	r.NextAction = "Enable TLS certificate verification before relying on trust-store remediation."
	return r
}
func nativeVersion(data []byte) string {
	// Runtime output is untrusted: never copy raw diagnostics into a report.
	return nativeVersionPattern.FindString(strings.TrimSpace(string(data)))
}

var nativeVersionPattern = regexp.MustCompile(`^(OpenSSL|LibreSSL|curl|macOS) [0-9][0-9A-Za-z.+_-]{0,40}\b`)

func nativeFixtureValid(c incident.Chain) bool {
	if len(c.Certificates) < 2 || len(c.AffectedSPKIs) == 0 {
		return false
	}
	now := time.Now()
	for _, cert := range c.Certificates {
		if cert == nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return false
		}
	}
	matched := false
	for index, cert := range c.Certificates[1:] {
		if c.Certificates[index].CheckSignatureFrom(cert) != nil {
			return false
		}
		key := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		for _, affected := range c.AffectedSPKIs {
			if strings.EqualFold(hex.EncodeToString(key[:]), affected) {
				matched = true
			}
		}
	}
	sum := sha256.Sum256(c.Certificates[0].Raw)
	return matched && strings.EqualFold(hex.EncodeToString(sum[:]), c.LeafSHA256) && c.Certificates[0].VerifyHostname(c.Hostname) == nil
}
