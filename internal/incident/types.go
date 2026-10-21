package incident

import "crypto/x509"

type Certificate struct {
	Name        string            `json:"name"`
	Usage       string            `json:"usage"`
	SHA256      string            `json:"sha256"`
	SPKI_SHA256 string            `json:"spki_sha256"`
	PEM         string            `json:"pem"`
	Parsed      *x509.Certificate `json:"-"`
}

type Chain struct {
	ID            string
	Hostname      string
	LeafSHA256    string
	PEM           []byte
	Certificates  []*x509.Certificate
	AffectedSPKIs []string
}

type Incident struct {
	ID            string
	Version       string
	SHA256        string
	Source        string
	Chains        []Chain
	Roots         []Certificate
	Intermediates []Certificate
}
