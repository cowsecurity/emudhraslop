// Package config validates explicit execution contexts without echoing secrets.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/platform"
)

// Limits bound untrusted inventory parsing, not machine coverage. Split larger
// inventories into separate scans; never silently truncate them.
const MaxManifestBytes = 1 << 20
const MaxTargets = 256

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$`)

type manifest struct {
	SchemaVersion int            `json:"schema_version"`
	Services      []model.Target `json:"services"`
}

func Load(path string) ([]model.Target, error) {
	f, err := platform.OpenRead(path)
	if err != nil {
		return nil, errors.New("cannot open service manifest")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("service manifest must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	if err != nil || len(data) > MaxManifestBytes {
		return nil, errors.New("service manifest exceeds readable size limit")
	}
	// Duplicate object keys otherwise silently replace earlier security settings.
	if err := uniqueJSON(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m manifest
	if dec.Decode(&m) != nil {
		return nil, errors.New("invalid service manifest fields")
	}
	if m.SchemaVersion != 1 {
		return nil, errors.New("unsupported service manifest schema")
	}
	if len(m.Services) == 0 || len(m.Services) > MaxTargets {
		return nil, errors.New("service manifest needs between 1 and 256 services")
	}
	seen := make(map[string]bool)
	for i := range m.Services {
		t := &m.Services[i]
		if !identifier.MatchString(t.ID) || seen[t.ID] {
			return nil, errors.New("service IDs must be unique safe identifiers")
		}
		seen[t.ID] = true
		if err := validateTarget(t); err != nil {
			return nil, err
		}
	}
	return m.Services, nil
}

func validateTarget(t *model.Target) error {
	if !identifier.MatchString(t.Kind) || (t.Client != "" && !identifier.MatchString(t.Client)) {
		return errors.New("invalid service kind or client")
	}
	if t.Executable != "" && !validPath(t.Executable) {
		return errors.New("service executable must be an absolute clean path")
	}
	for _, p := range []string{t.CABundle, t.CADir} {
		if p != "" && !validPath(p) {
			return errors.New("CA paths must be absolute clean paths")
		}
	}
	if t.ExclusiveCABundle && (t.Kind != "openssl" || t.CABundle == "" || t.CADir != "" || len(t.Environment) > 0) {
		return errors.New("exclusive CA-file mode requires OpenSSL, one explicit CA bundle and no extra trust settings")
	}
	if err := ValidateEnvironment(t.Environment); err != nil {
		return err
	}
	if len(t.ImageDigest) > 256 || strings.ContainsAny(t.ImageDigest, "\x00\r\n") {
		return errors.New("invalid image digest metadata")
	}
	if t.UID == nil {
		u, g := uint32(os.Geteuid()), uint32(os.Getegid())
		t.UID = &u
		if t.GID == nil {
			t.GID = &g
		}
	} else if t.GID == nil {
		if *t.UID != uint32(os.Geteuid()) {
			return errors.New("another execution identity requires an explicit gid")
		}
		g := uint32(os.Getegid())
		t.GID = &g
	}
	if os.Geteuid() != 0 && (*t.UID != uint32(os.Geteuid()) || *t.GID != uint32(os.Getegid())) {
		return errors.New("execution identity is unavailable without privilege")
	}
	if t.Client == "" {
		t.Client = defaultClient(t.Kind)
	}
	if t.Kind == "node" && t.Environment["NODE_TLS_REJECT_UNAUTHORIZED"] == "0" {
		t.VerificationDisabled = true
	}
	if !Supported(t.Kind, t.Client) {
		t.MetadataOnly = true
	}
	if t.Executable == "" && !t.MetadataOnly {
		return errors.New("supported service requires an absolute executable")
	}
	t.Source = "service-manifest"
	return nil
}

func validPath(path string) bool {
	return platform.ValidPath(path)
}

func defaultClient(kind string) string {
	switch kind {
	case "python":
		return "stdlib"
	case "node":
		return "tls"
	case "apple":
		return "security-framework"
	case "curl", "openssl":
		return kind
	}
	return "unsupported"
}

func Supported(kind, client string) bool {
	switch kind {
	case "python":
		return client == "stdlib" || client == "requests" || client == "httpx" || client == "botocore" || client == "urllib3" || client == "aiohttp"
	case "node":
		return client == "tls" || client == "https" || client == "fetch"
	case "apple":
		return client == "security-framework" || client == "sectrust-helper"
	case "curl", "openssl":
		return client == kind
	}
	return false
}

// uniqueJSON rejects duplicate keys at every nesting level and trailing values.
func uniqueJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("service manifest nesting limit exceeded")
		}
		tok, err := d.Token()
		if err != nil {
			return errors.New("invalid service manifest JSON")
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return errors.New("invalid service manifest JSON")
				}
				key, ok := k.(string)
				if !ok || keys[key] {
					return errors.New("duplicate service manifest field")
				}
				// encoding/json otherwise accepts case-folded struct fields,
				// permitting two spellings to override one security setting.
				// Environment keys at depth three are deliberately case-sensitive.
				if depth != 3 && key != strings.ToLower(key) {
					return errors.New("service manifest field spelling is invalid")
				}
				keys[key] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid service manifest JSON")
		}
		_, err = d.Token()
		if err != nil {
			return errors.New("invalid service manifest JSON")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing service manifest data")
	}
	return nil
}
