package probe

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/platform"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

const opensslBundleLimit = 32 << 20

// Snapshot the entire regular file; partial reads and unsupported PEM forms must
// never erase a trusted key. Comments and blank lines are the only extra text.
func opensslReadBundle(path string) ([]byte, []*x509.Certificate, error) {
	f, err := platform.OpenRead(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > opensslBundleLimit {
		return nil, nil, errors.New("unsupported CA file")
	}
	b, err := io.ReadAll(io.LimitReader(f, opensslBundleLimit+1))
	if err != nil || len(b) > opensslBundleLimit {
		return nil, nil, errors.New("incomplete CA file")
	}
	remaining := b
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if remaining[0] == '#' {
			_, remaining, _ = bytes.Cut(remaining, []byte("\n"))
			continue
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) || len(certs) >= 2048 {
			return nil, nil, errors.New("unsupported CA file contents")
		}
		footer := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(remaining, footer)
		if end < 0 {
			return nil, nil, errors.New("unterminated CA certificate")
		}
		end += len(footer)
		encoded := remaining[:end]
		block, remainder := pem.Decode(encoded)
		if block == nil || len(bytes.TrimSpace(remainder)) != 0 || bytes.Count(encoded, []byte("-----BEGIN ")) != 1 || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, nil, errors.New("invalid CA certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs, remaining = append(certs, cert), remaining[end:]
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("empty CA file")
	}
	return b, certs, nil
}

func opensslNegativePolicy(in *incident.Incident, certs []*x509.Certificate) (*x509.Certificate, bool) {
	canonical, err := incident.Load()
	if err != nil || in.ID != canonical.ID || in.SHA256 != canonical.SHA256 || len(in.Chains) != len(canonical.Chains) || canonical.Validate(time.Now()) != nil {
		return nil, false
	}
	// Compare actual certificate identities, rather than trusting an inherited
	// manifest label or a caller that removed a failed fixture from the set.
	for i, chain := range canonical.Chains {
		got := in.Chains[i]
		if got.ID != chain.ID || got.Hostname != chain.Hostname || got.LeafSHA256 != chain.LeafSHA256 || len(got.Certificates) != len(chain.Certificates) || !nativeFixtureValid(got) {
			return nil, false
		}
		for j, cert := range chain.Certificates {
			if !bytes.Equal(got.Certificates[j].Raw, cert.Raw) {
				return nil, false
			}
		}
	}
	anchors := canonical.KnownAnchors()
	var control *x509.Certificate
	now := time.Now()
	for _, cert := range certs {
		if canonical.IsAffected(incident.SPKI(cert)) || anchors[incident.SPKI(cert)] {
			return nil, false
		}
		if control == nil && cert.IsCA && now.After(cert.NotBefore) && now.Before(cert.NotAfter) && cert.CheckSignatureFrom(cert) == nil {
			control = cert
		}
	}
	return control, control != nil
}

var opensslVerifyError = regexp.MustCompile(`(?m)^error ([0-9]+) at [0-9]+ depth lookup:`)

func opensslIssuerRejection(out run.Output, err error, leafPath string) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || out.ExitCode != 2 || len(out.Stdout) != 0 || !bytes.Contains(out.Stderr, []byte("error "+leafPath+": verification failed")) {
		return false
	}
	matches := opensslVerifyError.FindAllSubmatch(out.Stderr, -1)
	if len(matches) == 0 {
		return false
	}
	for _, match := range matches {
		if string(match[1]) != "20" && string(match[1]) != "21" {
			return false
		}
	}
	return true
}
