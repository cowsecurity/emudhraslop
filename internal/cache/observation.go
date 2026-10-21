package cache

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

// Observation is historical evidence, never a revalidated machine verdict.
// Files are protected by the current owner's permissions, not a signature;
// a compromised owner can replace its own historical evidence.
type Observation struct {
	LastObservedStatus *model.Status `json:"last_observed_status"`
	ObservedAt         *time.Time    `json:"observed_at"`
	CurrentStatus      model.Status  `json:"current_status"`
	State              string        `json:"state"`
}

func unavailableObservation() Observation {
	return Observation{CurrentStatus: model.Unknown, State: "invalid"}
}

// Observe reads an owner-private report without executing any runtime or
// examining current trust files. Version/incident mismatches are not reusable.
func Observe(path, version, manifestHash string, maxAge time.Duration) Observation {
	result := unavailableObservation()
	if version == "" || maxAge <= 0 || maxAge > 7*24*time.Hour {
		return result
	}
	data, err := readObservation(path)
	if err != nil || !uniqueObservationJSON(data) || !observationShape(data) {
		return result
	}
	var report model.Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil {
		return result
	}
	if decoder.Decode(new(any)) != io.EOF {
		return result
	}
	now := time.Now().UTC()
	if !report.ValidAssessmentScope() || report.Version != version ||
		report.Incident != "emudhra-2026" || report.ManifestSHA256 != manifestHash ||
		report.ManifestVersion == "" || report.ScanTime.IsZero() || report.ScanTime.After(now) ||
		(report.Mode != "online" && report.Mode != "offline") || !validObservationDecisions(report) {
		return result
	}
	result.LastObservedStatus, result.ObservedAt = &report.Status, &report.ScanTime
	result.State = "fresh"
	if now.Sub(report.ScanTime) > maxAge {
		result.State = "stale"
	}
	return result
}

func validObservationDecisions(report model.Report) bool {
	// The normal scanner's aggregate: a positive takes priority, otherwise any
	// omitted/unknown context or report error prevents a negative decision.
	aggregate := model.NotAffected
	if len(report.Results) == 0 || !report.Coverage.Complete || len(report.Errors) > 0 {
		aggregate = model.Unknown
	}
	seen := map[string]bool{}
	affected := false
	for _, result := range report.Results {
		if result.ID == "" || seen[result.ID] || !matchingDecision(result.Status, result.Affected) {
			return false
		}
		seen[result.ID] = true
		if result.Status == model.Affected {
			affected = true
		}
		if result.Status == model.Unknown {
			aggregate = model.Unknown
		}
	}
	if affected {
		aggregate = model.Affected
	}
	return report.Status == aggregate && matchingDecision(report.Status, report.Affected)
}

func matchingDecision(status model.Status, affected *bool) bool {
	switch status {
	case model.Affected:
		return affected != nil && *affected
	case model.NotAffected:
		return affected != nil && !*affected
	case model.Unknown:
		return affected == nil
	default:
		return false
	}
}

// encoding/json permits duplicate and case-folded keys. Historical evidence
// must have one unambiguous spelling for each field, including nested objects.
func uniqueObservationJSON(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				token, err = decoder.Token()
				if err != nil {
					return false
				}
				key, ok := token.(string)
				if !ok || key != strings.ToLower(key) || seen[key] {
					return false
				}
				seen[key] = true
				if !walk(depth + 1) {
					return false
				}
			}
		case '[':
			for decoder.More() {
				if !walk(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		_, err = decoder.Token()
		return err == nil
	}
	if !walk(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

// Require even nullable fields: a truncated report must not be mistaken for a
// valid unknown observation merely because Go supplies zero values.
func observationShape(data []byte) bool {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	if !hasFields(root, "schema_version", "checker_version", "incident", "manifest_version", "manifest_sha256", "scan_time", "status", "affected", "mode", "coverage", "results", "errors", "configuration_sha256", "container", "assessment_scope", "application_status") {
		return false
	}
	var coverage map[string]json.RawMessage
	if json.Unmarshal(root["coverage"], &coverage) != nil || !hasFields(coverage, "scope", "complete", "exclusions", "warnings") {
		return false
	}
	var results []map[string]json.RawMessage
	if json.Unmarshal(root["results"], &results) != nil {
		return false
	}
	for _, result := range results {
		if !hasFields(result, "id", "kind", "uid", "configuration_source", "status", "affected", "reason", "next_action", "control_ok", "assessment_basis", "application_status") {
			return false
		}
	}
	return true
}

func hasFields(object map[string]json.RawMessage, names ...string) bool {
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return false
		}
	}
	return true
}
