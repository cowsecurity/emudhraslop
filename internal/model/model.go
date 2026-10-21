package model

import "time"

const SchemaVersion = 2

type Status string

const (
	Affected    Status = "affected"
	NotAffected Status = "not_affected"
	Unknown     Status = "unknown"
)

// Target describes one explicit client configuration, not all clients in a process.
type Target struct {
	ID                   string            `json:"id"`
	Kind                 string            `json:"kind"`
	Executable           string            `json:"executable,omitempty"`
	Client               string            `json:"client,omitempty"`
	UID                  *uint32           `json:"uid,omitempty"`
	GID                  *uint32           `json:"gid,omitempty"`
	CABundle             string            `json:"ca_bundle,omitempty"`
	CADir                string            `json:"ca_dir,omitempty"`
	ExclusiveCABundle    bool              `json:"exclusive_ca_bundle,omitempty"`
	Environment          map[string]string `json:"environment,omitempty"`
	ImageDigest          string            `json:"image_digest,omitempty"`
	Source               string            `json:"source"`
	VerificationDisabled bool              `json:"verification_disabled,omitempty"`
	MetadataOnly         bool              `json:"metadata_only,omitempty"`
}

type TrustSource struct {
	Path        string   `json:"path"`
	SHA256      string   `json:"sha256,omitempty"`
	Complete    bool     `json:"complete"`
	MatchedKeys []string `json:"matched_keys,omitempty"`
}

type Check struct {
	ChainID    string `json:"chain_id"`
	Outcome    string `json:"outcome"`
	Proof      string `json:"proof,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
}

type Result struct {
	ID                string        `json:"id"`
	Kind              string        `json:"kind"`
	Client            string        `json:"client,omitempty"`
	Executable        string        `json:"executable,omitempty"`
	RuntimeVersion    string        `json:"runtime_version,omitempty"`
	UID               uint32        `json:"uid"`
	ImageDigest       string        `json:"image_digest,omitempty"`
	Source            string        `json:"configuration_source"`
	AssessmentBasis   string        `json:"assessment_basis"`
	ApplicationStatus Status        `json:"application_status"`
	ExclusiveCABundle bool          `json:"exclusive_ca_bundle,omitempty"`
	Status            Status        `json:"status"`
	Affected          *bool         `json:"affected"`
	Reason            string        `json:"reason"`
	NextAction        string        `json:"next_action"`
	TrustSources      []TrustSource `json:"trust_sources,omitempty"`
	Checks            []Check       `json:"checks,omitempty"`
	ControlOK         bool          `json:"control_ok"`
	Fingerprint       string        `json:"configuration_hash,omitempty"`
}

type Coverage struct {
	Scope      string   `json:"scope"`
	Complete   bool     `json:"complete"`
	Exclusions []string `json:"exclusions"`
	Warnings   []string `json:"warnings"`
}

type Report struct {
	SchemaVersion       int       `json:"schema_version"`
	AssessmentScope     string    `json:"assessment_scope"`
	ApplicationStatus   Status    `json:"application_status"`
	Version             string    `json:"checker_version"`
	Incident            string    `json:"incident"`
	ManifestVersion     string    `json:"manifest_version"`
	ManifestSHA256      string    `json:"manifest_sha256"`
	ScanTime            time.Time `json:"scan_time"`
	Status              Status    `json:"status"`
	Affected            *bool     `json:"affected"`
	Mode                string    `json:"mode"`
	Coverage            Coverage  `json:"coverage"`
	Results             []Result  `json:"results"`
	Errors              []string  `json:"errors"`
	ConfigurationSHA256 string    `json:"configuration_sha256"`
	Container           bool      `json:"container"`
}

func NewResult(t Target) Result {
	uid := uint32(0)
	if t.UID != nil {
		uid = *t.UID
	}
	basis := "client_defaults"
	if t.CABundle != "" || t.CADir != "" || len(t.Environment) != 0 || t.ExclusiveCABundle || t.VerificationDisabled {
		basis = "configured_client"
	}
	return Result{ID: t.ID, Kind: t.Kind, Client: t.Client, Executable: t.Executable, UID: uid,
		AssessmentBasis: basis, ApplicationStatus: Unknown,
		ImageDigest: t.ImageDigest, Source: t.Source, ExclusiveCABundle: t.ExclusiveCABundle, Status: Unknown,
		Reason: "not_checked", NextAction: "Run a supported native client check."}
}

// No current adapter executes within a running application. Stored evidence
// must retain this boundary rather than acquire an application verdict on read.
func (r Report) ValidAssessmentScope() bool {
	if r.SchemaVersion != SchemaVersion || r.AssessmentScope != "client_configurations" || r.ApplicationStatus != Unknown {
		return false
	}
	for _, result := range r.Results {
		if result.ApplicationStatus != Unknown || (result.AssessmentBasis != "client_defaults" && result.AssessmentBasis != "configured_client") {
			return false
		}
	}
	return true
}
