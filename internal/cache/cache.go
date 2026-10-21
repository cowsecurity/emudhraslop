//go:build !windows

// Package cache stores owner-private evidence. A cache is an optimization,
// never a substitute for effective native-policy attestation.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

const maxReportBytes = 16 << 20
const maxTrustBytes = 64 << 20

// Bound total cache validation I/O even when many distinct sources are listed.
const maxTotalTrustBytes = 128 << 20

var ErrInvalid = errors.New("cache is unavailable, unsafe, stale, or lacks reusable evidence")

// Save atomically replaces a private cache, without changing report semantics.
// Concurrent replacement may invalidate a security inspection and return
// ErrInvalid. A rejected writer does not remove the previously published cache.
func Save(path string, report model.Report) error {
	if err := prepare(path); err != nil {
		return ErrInvalid
	}
	data, err := json.Marshal(report)
	if err != nil || len(data) > maxReportBytes {
		return ErrInvalid
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".emudhraslop-cache-")
	if err != nil {
		return ErrInvalid
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return ErrInvalid
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return ErrInvalid
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return ErrInvalid
	}
	if err := f.Close(); err != nil {
		return ErrInvalid
	}
	if err := inspect(path, false); err != nil {
		return ErrInvalid
	}
	if err := os.Rename(name, path); err != nil {
		return ErrInvalid
	}
	d, err := os.Open(dir)
	if err != nil {
		return ErrInvalid
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return ErrInvalid
	}
	return nil
}

// Load invalidates on tool, manifest, configuration, age or trust-file changes.
// Protected results deliberately require a fresh scan: this report format has
// no authenticated complete-effective-policy attestation suitable for reuse.
func Load(path, version, manifestHash, configurationHash string, maxAge time.Duration) (model.Report, error) {
	var report model.Report
	if maxAge <= 0 || version == "" || !validHash(manifestHash) || !validHash(configurationHash) {
		return report, ErrInvalid
	}
	if err := inspect(path, true); err != nil {
		return report, ErrInvalid
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return report, ErrInvalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !private(info, false) || info.Size() > maxReportBytes {
		return report, ErrInvalid
	}
	decoder := json.NewDecoder(io.LimitReader(f, maxReportBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return model.Report{}, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return model.Report{}, ErrInvalid
	}
	now := time.Now()
	if !report.ValidAssessmentScope() || report.Version != version || report.ManifestSHA256 != manifestHash || report.ConfigurationSHA256 != configurationHash || report.ScanTime.IsZero() || report.ScanTime.After(now) || now.Sub(report.ScanTime) > maxAge || len(report.Results) == 0 {
		return model.Report{}, ErrInvalid
	}
	if report.Status != model.Affected && report.Status != model.Unknown {
		return model.Report{}, ErrInvalid
	}
	foundAffected := false
	seen := make(map[string]bool, len(report.Results))
	verified := make(map[string]string)
	remaining := int64(maxTotalTrustBytes)
	for _, result := range report.Results {
		if result.ID == "" || seen[result.ID] || (result.Status != model.Affected && result.Status != model.Unknown) {
			return model.Report{}, ErrInvalid
		}
		seen[result.ID] = true
		if result.Status == model.Affected {
			if len(result.TrustSources) == 0 {
				return model.Report{}, ErrInvalid
			}
			foundAffected = true
		}
		for _, source := range result.TrustSources {
			if !source.Complete || !validHash(source.SHA256) || !filepath.IsAbs(source.Path) {
				return model.Report{}, ErrInvalid
			}
			if hash, ok := verified[source.Path]; ok {
				if hash != source.SHA256 {
					return model.Report{}, ErrInvalid
				}
			} else {
				if err := verifySourceBudget(source, &remaining); err != nil {
					return model.Report{}, ErrInvalid
				}
				verified[source.Path] = source.SHA256
			}
		}
	}
	if (report.Status == model.Affected) != foundAffected {
		return model.Report{}, ErrInvalid
	}
	report.Mode = "cached"
	return report, nil
}

func verifySourceBudget(source model.TrustSource, remaining *int64) error {
	// Nonblocking open prevents a replaced FIFO/device from hanging before Stat.
	f, err := os.OpenFile(source.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ErrInvalid
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxTrustBytes || before.Size() > *remaining {
		return ErrInvalid
	}
	h := sha256.New()
	limit := min(int64(maxTrustBytes), *remaining)
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil || n > limit {
		return ErrInvalid
	}
	*remaining -= n
	if *remaining < 0 {
		return ErrInvalid
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || hex.EncodeToString(h.Sum(nil)) != source.SHA256 {
		return ErrInvalid
	}
	current, err := os.Stat(source.Path)
	if err != nil || !os.SameFile(before, current) || current.Size() != after.Size() || !current.ModTime().Equal(after.ModTime()) {
		return ErrInvalid
	}
	return nil
}

func validHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func prepare(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		if err := inspectAncestors(filepath.Dir(dir)); err != nil {
			return ErrInvalid
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			return ErrInvalid
		}
	} else if err != nil {
		return ErrInvalid
	}
	return inspect(path, false)
}

func inspect(path string, required bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalid
	}
	if err := inspectAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !private(dir, true) {
		return ErrInvalid
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) && !required {
		return nil
	}
	if err != nil || !private(info, false) {
		return ErrInvalid
	}
	return nil
}

func private(info os.FileInfo, directory bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm()&0700 == 0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0600 == 0600 && st.Nlink == 1
}

func inspectAncestors(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return ErrInvalid
		}
		// A root-owned sticky temporary ancestor is acceptable only to a
		// non-root caller whose immediate cache directory is private.
		stickyTemp := os.Geteuid() != 0 && st.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if info.Mode().Perm()&0022 != 0 && !stickyTemp {
			return ErrInvalid
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
