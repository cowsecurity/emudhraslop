package app

import "github.com/cowsecurity/emudhraslop/internal/model"

func humanReason(reason string) string {
	switch reason {
	case "native_client_accepts_incident_chain", "native_client_accepted_incident_fixture":
		return "This client trusted a certificate chain from the eMudhra incident."
	case "tls_verification_disabled", "tls_verification_explicitly_disabled", "verification_disabled":
		return "Certificate verification is disabled in this client configuration."
	case "known_incident_tls_paths_not_trusted_by_explicit_openssl_bundle":
		return "The declared, exclusive OpenSSL CA file does not trust the known incident TLS chains; the native verification controls passed."
	case "native_rejections_not_attributed", "native_rejections_do_not_prove_protection":
		return "No incident-chain acceptance was confirmed, but the reason for rejection or failure does not prove protection."
	case "openssl_explicit_trust_context_required":
		return "OpenSSL was found, but the CA file or directory used by the application was not specified."
	case "offline_native_policy_not_proven":
		return "Offline evidence cannot establish this client's TLS trust decision."
	case "curl_requires_online_native_probe":
		return "curl needs an online check to test its TLS trust decision."
	case "inventory_only":
		return "This client was listed but no check was run."
	case "unsupported_or_incomplete_context", "unsupported_runtime":
		return "This application or its TLS settings cannot be checked by the available adapters."
	case "clean_control_failed":
		return "The normal HTTPS control connection failed; network, proxy or trust settings need investigation."
	case "root_probe_denied", "root_package_import_denied", "root_python_execution_denied":
		return "The probe was refused because it would execute a client with elevated privileges."
	case "native_execution_unavailable", "runtime_probe_failed":
		return "The native client could not run successfully."
	case "scan_deadline", "probe_timeout":
		return "The check ran out of time before it could establish a result."
	case "scan_cancelled":
		return "The check was cancelled before it could establish a result."
	case "probe_output_limit":
		return "The client produced more output than the safety limit allows; its result is incomplete."
	case "unsupported_environment", "unsupported_node_options", "unsupported_proxy_configuration":
		return "The client has environment or proxy settings that this checker cannot safely reproduce."
	case "unsupported_python_client", "unsupported_node_client":
		return "This TLS client needs an adapter that can verify the peer certificate identity."
	case "package_unavailable":
		return "This optional HTTP client library is not available in the selected Python environment."
	case "unsupported_client":
		return "The selected runtime does not expose the client features required for this check."
	case "unsupported_configuration", "unsupported_node_fetch_ca_configuration":
		return "This adapter cannot reproduce the supplied trust settings; this client remains unknown."
	case "trust_source_unreadable":
		return "The client's trust source could not be read."
	case "unsupported_node_ca_directory", "apple_custom_trust_context_unsupported", "unsupported_exclusive_ca_bundle_context":
		return "The declared trust configuration is not supported by this probe."
	case "apple_trust_unavailable_on_platform":
		return "Apple trust checks are available only on macOS."
	case "sectrust_helper_unavailable_or_timed_out":
		return "The macOS trust helper could not run or timed out."
	case "sectrust_helper_response_invalid", "invalid_probe_response":
		return "The native probe returned an invalid response."
	case "fixture_directory_unavailable", "native_helper_unavailable", "native_helper_cache_unavailable", "fixture_write_failed":
		return "The local test files or helper could not be prepared."
	case "no_valid_incident_fixtures", "fixture_validation_failed":
		return "The embedded incident certificates failed validation or are no longer valid for this check."
	case "explicit_ca_bundle_incomplete":
		return "The declared CA file could not be read and validated completely."
	case "trust_policy_changed_during_probe", "configuration_changed_during_scan":
		return "The runtime or trust configuration changed during the scan; negative results are inconclusive."
	case "negative_proof_control_or_policy_stability_failed":
		return "The verification controls or stable-trust checks required to prove protection did not pass."
	case "configuration_fingerprint_incomplete":
		return "The executable or trust files could not be fully fingerprinted; negative results are inconclusive."
	case "cache_missing_stale_or_unverifiable":
		return "The saved report is missing, too old or cannot be validated for this configuration."
	case "cache_write_failed":
		return "The requested report cache could not be written."
	case "not_checked", "":
		return "This client has not been checked."
	default:
		// Future reasons remain visible rather than being generalized away.
		return "Check detail: " + reason
	}
}

func humanAdvice(r model.Result) string {
	switch r.Reason {
	case "inventory_only", "offline_native_policy_not_proven", "curl_requires_online_native_probe":
		return "Run emudhraslop check --online with the same --project or --services selection, if one was supplied."
	case "native_rejections_do_not_prove_protection", "clean_control_failed":
		return "Check this client's network, proxy and trust settings. Use --agent for per-certificate evidence; do not treat a failed connection as protection."
	case "root_probe_denied", "root_package_import_denied", "root_python_execution_denied":
		return "Run as the ordinary user or service account that runs this application."
	case "native_execution_unavailable", "runtime_probe_failed", "invalid_probe_response":
		return "Check that the listed executable and TLS client are available to this user, then rerun."
	case "cache_missing_stale_or_unverifiable", "cache_write_failed":
		return "Run a fresh check without --cache or --cached; add --online for network checks."
	case "no_valid_incident_fixtures", "fixture_validation_failed":
		return "Check the system clock and use the latest checker release before retrying."
	}
	if r.NextAction != "" {
		return r.NextAction
	}
	return "Inspect this client configuration and rerun the check; use --agent for the complete evidence."
}
