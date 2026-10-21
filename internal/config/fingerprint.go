package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/platform"
)

const maxFileBytes int64 = 512 << 20 // accommodates native runtime executables
const maxCABytes int64 = 32 << 20
const maxDirectoryEntries = 4096
const maxFingerprintBytes int64 = 1 << 30

// Fingerprint binds declared context, executable bytes and explicit CA sources.
// It does NOT prove that implicit runtime/system trust sources are complete.
// Cache consumers must additionally validate complete probe TrustSources.
func Fingerprint(targets []model.Target) (string, error) {
	h := sha256.New()
	ordered := append([]model.Target(nil), targets...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	data, err := json.Marshal(ordered)
	if err != nil {
		return "", errors.New("cannot fingerprint service configuration")
	}
	h.Write(data)
	budget := maxFingerprintBytes
	seen := map[string]bool{}
	for _, t := range ordered {
		if t.Executable != "" {
			if err := hashFile(h, t.Executable, maxFileBytes, &budget, seen); err != nil {
				return "", err
			}
		}
		files := []string{t.CABundle}
		dirs := []string{t.CADir}
		for key, value := range t.Environment {
			switch key {
			case "SSL_CERT_DIR":
				dirs = append(dirs, filepath.SplitList(value)...)
			case "SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS":
				files = append(files, value)
			}
		}
		sort.Strings(files)
		sort.Strings(dirs)
		for _, path := range files {
			if path != "" {
				if err := hashFile(h, path, maxCABytes, &budget, seen); err != nil {
					return "", err
				}
			}
		}
		for _, path := range dirs {
			if path != "" {
				if err := hashDirectory(h, path, &budget, seen); err != nil {
					return "", err
				}
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFile(h hash.Hash, path string, limit int64, budget *int64, seen map[string]bool) error {
	if !validPath(path) {
		return errors.New("cannot fingerprint non-absolute context file")
	}
	if seen[path] {
		return nil
	}
	seen[path] = true
	f, err := platform.OpenRead(path)
	if err != nil {
		return errors.New("context file unavailable for fingerprint")
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return errors.New("context fingerprint requires regular files")
	}
	if before.Size() > limit || before.Size() > *budget {
		return errors.New("context fingerprint resource limit exceeded")
	}
	h.Write([]byte("\x00file\x00" + path + "\x00"))
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	*budget -= n
	if err != nil || n > limit || *budget < 0 {
		return errors.New("context file could not be fully fingerprinted")
	}
	after, err := f.Stat()
	current, statErr := os.Stat(path)
	if err != nil || statErr != nil || !os.SameFile(before, current) || before.Size() != n || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("context file changed during fingerprint")
	}
	return nil
}

func hashDirectory(h hash.Hash, path string, budget *int64, seen map[string]bool) error {
	if !validPath(path) {
		return errors.New("cannot fingerprint non-absolute trust directory")
	}
	f, err := platform.OpenRead(path)
	if err != nil {
		return errors.New("trust directory unavailable for fingerprint")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() {
		return errors.New("trust source must be a directory")
	}
	entries, err := f.ReadDir(maxDirectoryEntries + 1)
	if (err != nil && err != io.EOF) || len(entries) > maxDirectoryEntries {
		return errors.New("trust directory fingerprint resource limit exceeded")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	h.Write([]byte("\x00directory\x00" + path + "\x00"))
	for _, entry := range entries {
		// CApath directories are flat. A nested directory could hide trust data;
		// conservatively invalidate rather than silently exclude it.
		if entry.IsDir() {
			return errors.New("nested trust directory cannot be completely fingerprinted")
		}
		if err := hashFile(h, filepath.Join(path, entry.Name()), maxCABytes, budget, seen); err != nil {
			return err
		}
	}
	after, err := f.Stat()
	current, statErr := os.Stat(path)
	if err != nil || statErr != nil || !os.SameFile(info, current) || !after.ModTime().Equal(info.ModTime()) {
		return errors.New("trust directory changed during fingerprint")
	}
	return nil
}
