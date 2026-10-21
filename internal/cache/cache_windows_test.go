package cache

import (
	"errors"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsCacheNeverPretendsUnixModesAttestACLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := Save(path, model.Report{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("Windows cache write accepted without ACL attestation")
	}
	if _, err := Load(path, "v1", "manifest", "context", time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatal("Windows cache read accepted without ACL attestation")
	}
}
