package incident

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed data
var data embed.FS

func Hash(b []byte) string            { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func SPKI(c *x509.Certificate) string { return Hash(c.RawSubjectPublicKeyInfo) }

func Load() (*Incident, error) {
	manifest, err := data.ReadFile("data/integrity.json")
	if err != nil {
		return nil, err
	}
	var hashes map[string]string
	if json.Unmarshal(manifest, &hashes) != nil || len(hashes) == 0 {
		return nil, errors.New("invalid fixture integrity manifest")
	}
	names := make([]string, 0, len(hashes))
	for n := range hashes {
		names = append(names, n)
	}
	sort.Strings(names)
	payload := map[string][]byte{}
	for _, n := range names {
		if strings.Contains(n, "..") || filepath.IsAbs(n) {
			return nil, errors.New("invalid fixture path")
		}
		b, e := data.ReadFile("data/" + n)
		if e != nil || Hash(b) != hashes[n] {
			return nil, fmt.Errorf("fixture integrity failure: %s", n)
		}
		payload[n] = b
	}
	inc := &Incident{ID: "emudhra-2026", Version: "2026-10-20.1", SHA256: Hash(manifest), Source: "https://emudhra.we-have-a-problem.com/"}
	if json.Unmarshal(payload["roots.json"], &inc.Roots) != nil || json.Unmarshal(payload["impacted-intermediates.json"], &inc.Intermediates) != nil {
		return nil, errors.New("invalid certificate manifest")
	}
	seen := map[string]bool{}
	for _, list := range [][]Certificate{inc.Roots, inc.Intermediates} {
		for i := range list {
			certs, e := ParsePEM([]byte(list[i].PEM))
			if e != nil || len(certs) != 1 {
				return nil, errors.New("invalid manifest certificate")
			}
			c := certs[0]
			list[i].Parsed = c
			if !strings.EqualFold(Hash(c.Raw), list[i].SHA256) || !strings.EqualFold(SPKI(c), list[i].SPKI_SHA256) {
				return nil, errors.New("certificate identity mismatch")
			}
			if seen[Hash(c.Raw)] {
				return nil, errors.New("duplicate certificate identity")
			}
			seen[Hash(c.Raw)] = true
		}
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "chains/") {
			continue
		}
		certs, e := ParsePEM(payload[n])
		if e != nil || len(certs) < 2 {
			return nil, errors.New("invalid fixture chain")
		}
		id := strings.TrimSuffix(strings.TrimPrefix(n, "chains/"), ".pem")
		ch := Chain{ID: id, Hostname: id, PEM: payload[n], Certificates: certs, LeafSHA256: Hash(certs[0].Raw)}
		for _, c := range certs {
			if inc.IsAffected(SPKI(c)) {
				ch.AffectedSPKIs = append(ch.AffectedSPKIs, SPKI(c))
			}
		}
		if len(ch.AffectedSPKIs) == 0 {
			return nil, errors.New("fixture does not exercise an affected key")
		}
		inc.Chains = append(inc.Chains, ch)
	}
	if len(inc.Chains) == 0 {
		return nil, errors.New("missing fixture chains")
	}
	return inc, nil
}

// ParsePEM refuses non-certificate blocks and trailing garbage.
func ParsePEM(b []byte) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	for len(strings.TrimSpace(string(b))) > 0 {
		b = []byte(strings.TrimSpace(string(b)))
		if !strings.HasPrefix(string(b), "-----BEGIN CERTIFICATE-----") {
			return nil, errors.New("invalid certificate PEM prefix")
		}
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid DER certificate")
		}
		result = append(result, c)
		b = rest
	}
	if len(result) == 0 {
		return nil, errors.New("empty certificate PEM")
	}
	return result, nil
}

func (in *Incident) IsAffected(spki string) bool {
	for _, c := range in.Intermediates {
		if strings.EqualFold(c.SPKI_SHA256, spki) {
			return true
		}
	}
	return false
}
func (in *Incident) KnownAnchors() map[string]bool {
	out := map[string]bool{}
	for _, c := range in.Roots {
		out[strings.ToLower(c.SPKI_SHA256)] = true
	}
	return out
}

// Validate checks fixture validity and signatures without Go's trust-policy verifier.
// The target native verifier alone decides whether its effective trust accepts a chain.
func (in *Incident) Validate(now time.Time) error {
	for _, ch := range in.Chains {
		if len(ch.Certificates) < 2 {
			return errors.New("incomplete fixture chain")
		}
		leaf := ch.Certificates[0]
		if leaf.VerifyHostname(ch.Hostname) != nil {
			return errors.New("fixture hostname mismatch")
		}
		server := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				server = true
			}
		}
		if !server {
			return errors.New("fixture is not valid for TLS server authentication")
		}
		for i, c := range ch.Certificates {
			if now.Before(c.NotBefore) || now.After(c.NotAfter) {
				return errors.New("fixture certificate is outside its validity period")
			}
			if i+1 < len(ch.Certificates) {
				if c.CheckSignatureFrom(ch.Certificates[i+1]) != nil {
					return errors.New("fixture signature mismatch")
				}
			} else {
				found := false
				for _, root := range in.Roots {
					if c.CheckSignatureFrom(root.Parsed) == nil {
						found = true
						break
					}
				}
				if !found {
					return errors.New("fixture does not terminate at a known issuer")
				}
			}
		}
	}
	return nil
}
