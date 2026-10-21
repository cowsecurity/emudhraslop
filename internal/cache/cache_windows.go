package cache

import (
	"errors"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"time"
)

// Unix permission bits cannot attest Windows ACL ownership. Until a dedicated
// ACL validator exists, Windows always scans fresh and never trusts a cache.
var ErrInvalid = errors.New("cache is unavailable on Windows; use --no-cache for a fresh scan")

func Save(string, model.Report) error { return ErrInvalid }
func Load(string, string, string, string, time.Duration) (model.Report, error) {
	return model.Report{}, ErrInvalid
}
