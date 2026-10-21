package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func emit(out io.Writer, r model.Report, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	return emitHuman(out, r)
}

// Counts describe result rows (client configurations), never unique apps,
// packages or machines. Unrecognized statuses stay inconclusive.
func emitHuman(out io.Writer, r model.Report) error {
	var writeErr error
	line := func(format string, args ...any) {
		if writeErr == nil {
			_, writeErr = fmt.Fprintf(out, format+"\n", args...)
		}
	}
	affected, notAffected, unknown := 0, 0, 0
	for _, result := range r.Results {
		switch result.Status {
		case model.Affected:
			affected++
		case model.NotAffected:
			notAffected++
		default:
			unknown++
		}
	}
	if r.Mode == "inventory" {
		line("Inventory only: no client checks were run.")
	} else {
		switch r.Status {
		case model.Affected:
			line("AFFECTED: exposure was confirmed in at least one checked client configuration.")
		case model.NotAffected:
			line("NOT AFFECTED within the checked scope. Other applications are not covered.")
		default:
			line("UNKNOWN: the available checks cannot confirm protection.")
		}
	}
	line("Client configurations: %d total; %d affected, %d not affected, %d unknown.", len(r.Results), affected, notAffected, unknown)
	line("Incident: %s | Mode: %s | Scope: %s", terminal(r.Incident), terminal(r.Mode), terminal(r.Coverage.Scope))
	line("Application status: UNKNOWN. These isolated client checks do not test running applications or listening ports.")
	if !r.ScanTime.IsZero() {
		line("Checked at: %s", r.ScanTime.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if r.Container {
		line("This report covers clients inside this container, not the host or other containers.")
	}
	for _, result := range r.Results {
		line("")
		label := valueOr(result.Kind, "runtime unspecified")
		if result.Client != result.Kind {
			label += " / " + valueOr(result.Client, "client unspecified")
		}
		line("%s  %s  (%s)", statusLabel(result.Status), label, terminal(result.ID))
		line("  Executable: %s", valueOr(result.Executable, "not available"))
		line("  Version: %s", valueOr(result.RuntimeVersion, "not observed"))
		if result.AssessmentBasis == "configured_client" {
			line("  Tested: client with supplied trust settings. Application behavior: UNKNOWN.")
		} else {
			line("  Tested: client defaults. Application behavior: UNKNOWN.")
		}
		for _, source := range result.TrustSources {
			if source.Complete {
				line("  Trust file: %s", valueOr(source.Path, "path not reported"))
			} else {
				line("  Trust file (incomplete evidence): %s", valueOr(source.Path, "path not reported"))
			}
		}
		line("  Why: %s", terminal(humanReason(result.Reason)))
		line("  Next: %s", terminal(humanAdvice(result)))
	}
	line("")
	if r.Coverage.Complete {
		line("Coverage: all declared client configurations listed; application behavior remains unverified.")
	} else {
		line("Coverage: incomplete. This report does not clear the whole machine.")
	}
	for _, exclusion := range r.Coverage.Exclusions {
		line("  Not covered: %s", terminal(exclusion))
	}
	for _, warning := range r.Coverage.Warnings {
		line("  Warning: %s", terminal(warning))
	}
	for _, problem := range r.Errors {
		line("  Error: %s", terminal(humanReason(problem)))
	}
	if r.Mode == "inventory" {
		line("\nNext: run emudhraslop check --online to test these clients.")
	} else if affected > 0 {
		line("\nNext: update the affected clients' runtime/trust settings, restart services that use those settings, and rerun the same check.")
		line("An affected result shows trust exposure; it does not prove that an attack occurred.")
	}
	if r.Mode == "cached" {
		line("For machine-readable cached evidence: use --json. Use --agent for a fresh check.")
	} else {
		line("For automation or full evidence: add --agent to your command.")
	}
	return writeErr
}

func statusLabel(status model.Status) string {
	switch status {
	case model.Affected:
		return "AFFECTED"
	case model.NotAffected:
		return "NOT AFFECTED"
	case model.Unknown:
		return "UNKNOWN"
	default:
		return "UNKNOWN (status " + terminal(string(status)) + ")"
	}
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return terminal(value)
}

// Runtime output, paths and cached messages may contain terminal escapes or
// bidirectional formatting. Render those bytes visibly without hiding content.
// JSON keeps the original schema/data and already escapes C0 characters.
func terminal(value string) string {
	var b strings.Builder
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, "\\x%02x", value[0])
			value = value[1:]
			continue
		}
		value = value[size:]
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			escaped := strconv.QuoteRuneToASCII(r)
			b.WriteString(escaped[1 : len(escaped)-1])
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
