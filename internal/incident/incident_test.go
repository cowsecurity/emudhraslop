package incident

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedIdentityAndValidity(t *testing.T) {
	in, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Fixed time is a fixture validity oracle, not a substituted runtime clock.
	when := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := in.Validate(when); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ch := range in.Chains {
		if seen[ch.ID] {
			t.Fatal("duplicate fixture ID")
		}
		seen[ch.ID] = true
		if Hash(ch.Certificates[0].Raw) != ch.LeafSHA256 {
			t.Fatal("wrong leaf identity")
		}
		if len(ch.AffectedSPKIs) == 0 {
			t.Fatal("fixture bypasses incident key")
		}
		for _, spki := range ch.AffectedSPKIs {
			if !in.IsAffected(spki) {
				t.Fatal("unlisted key")
			}
		}
	}
	if err := in.Validate(when.AddDate(10, 0, 0)); err == nil {
		t.Fatal("expired fixtures accepted")
	}
}

func TestTamperedChainCannotValidate(t *testing.T) {
	in, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	in.Chains[0].Hostname = "unrelated.example"
	if in.Validate(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)) == nil {
		t.Fatal("hostname tampering accepted")
	}
	in, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	in.Chains[0].Certificates[1] = in.Roots[0].Parsed
	if in.Validate(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)) == nil {
		t.Fatal("issuer substitution accepted")
	}
}

func TestStrictPEM(t *testing.T) {
	in, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	p := []byte(in.Roots[0].PEM)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})
	for _, b := range [][]byte{nil, []byte("garbage"), append([]byte("junk\n"), p...), append(p, []byte("\njunk")...), key} {
		if _, err := ParsePEM(b); err == nil {
			t.Fatalf("accepted invalid PEM: %q", strings.SplitN(string(b), "\n", 2)[0])
		}
	}
}
