//go:build !windows

package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cowsecurity/emudhraslop/internal/model"
)

func fixture(t *testing.T) (string, model.Report) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := inspectAncestors(dir); err != nil {
		t.Skip("test temporary ancestry is intentionally untrusted for this execution identity")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(store, []byte("trust policy fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("trust policy fixture"))
	r := model.Report{SchemaVersion: model.SchemaVersion, AssessmentScope: "client_configurations", ApplicationStatus: model.Unknown, Version: "test", ManifestSHA256: strings.Repeat("a", 64), ConfigurationSHA256: strings.Repeat("b", 64), ScanTime: time.Now().UTC(), Status: model.Affected, Results: []model.Result{{ID: "service", AssessmentBasis: "client_defaults", ApplicationStatus: model.Unknown, Status: model.Affected, TrustSources: []model.TrustSource{{Path: store, SHA256: hex.EncodeToString(h[:]), Complete: true}}}}}
	return filepath.Join(dir, "cache.json"), r
}

func load(path string, report model.Report) (model.Report, error) {
	return Load(path, report.Version, report.ManifestSHA256, report.ConfigurationSHA256, time.Hour)
}

func TestPrivateRoundTripAndStoreMutation(t *testing.T) {
	path, r := fixture(t)
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := load(path, r)
	if err != nil || got.Status != model.Affected || got.Mode != "cached" {
		t.Fatalf("round trip: %#v %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("cache mode %v", info.Mode())
	}
	if err := os.WriteFile(r.Results[0].TrustSources[0].Path, []byte("changed trust policy"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, r); err == nil {
		t.Fatal("trust policy mutation reused stale acceptance")
	}
}

func TestStaleFutureContextAndForgedProtectionFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Report)
	}{
		{"stale", func(r *model.Report) { r.ScanTime = time.Now().Add(-2 * time.Hour) }},
		{"future", func(r *model.Report) { r.ScanTime = time.Now().Add(time.Hour) }},
		{"wrong tool", func(r *model.Report) { r.Version = "old" }},
		{"legacy scope", func(r *model.Report) { r.SchemaVersion = 1 }},
		{"forged application verdict", func(r *model.Report) { r.ApplicationStatus = model.NotAffected }},
		{"forged client application verdict", func(r *model.Report) { r.Results[0].ApplicationStatus = model.Affected }},
		{"missing basis", func(r *model.Report) { r.Results[0].AssessmentBasis = "" }},
		{"wrong manifest", func(r *model.Report) { r.ManifestSHA256 = strings.Repeat("c", 64) }},
		{"wrong context", func(r *model.Report) { r.ConfigurationSHA256 = strings.Repeat("d", 64) }},
		{"protected with rehashed file", func(r *model.Report) {
			r.Status = model.NotAffected
			r.Results[0].Status = model.NotAffected
			r.Results[0].ControlOK = true
		}},
		{"hidden protected result", func(r *model.Report) {
			r.Results = append(r.Results, model.Result{ID: "second", Status: model.NotAffected})
		}},
		{"missing trust policy", func(r *model.Report) { r.Results[0].TrustSources = nil }},
		{"partial trust policy", func(r *model.Report) { r.Results[0].TrustSources[0].Complete = false }},
		{"duplicate identity", func(r *model.Report) { r.Results = append(r.Results, r.Results[0]) }},
		{"hidden acceptance", func(r *model.Report) { r.Status = model.Unknown }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, expected := fixture(t)
			data, _ := json.Marshal(expected)
			var changed model.Report
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&changed)
			if err := Save(path, changed); err != nil {
				t.Fatal(err)
			}
			if _, err := load(path, expected); err == nil {
				t.Fatal("unsafe evidence was reused")
			}
		})
	}
}

func TestUnknownWithoutTrustEvidenceRemainsUnknown(t *testing.T) {
	path, r := fixture(t)
	r.Status = model.Unknown
	r.Results[0].Status = model.Unknown
	r.Results[0].TrustSources = nil
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	got, err := load(path, r)
	if err != nil || got.Status != model.Unknown {
		t.Fatalf("unknown reuse: %v", err)
	}
}

func TestSymlinksPublicPermissionsHardlinksAndTrailingDataRejected(t *testing.T) {
	for _, attack := range []string{"file symlink", "directory symlink", "public file", "public directory", "hardlink", "trailing JSON"} {
		t.Run(attack, func(t *testing.T) {
			path, r := fixture(t)
			if err := Save(path, r); err != nil {
				t.Fatal(err)
			}
			switch attack {
			case "file symlink":
				other := path + ".real"
				os.Rename(path, other)
				os.Symlink(other, path)
			case "directory symlink":
				link := filepath.Join(filepath.Dir(path), "linked")
				os.Symlink(filepath.Dir(path), link)
				path = filepath.Join(link, "cache.json")
			case "public file":
				os.Chmod(path, 0644)
			case "public directory":
				os.Chmod(filepath.Dir(path), 0755)
			case "hardlink":
				os.Link(path, path+".link")
			case "trailing JSON":
				f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				f.WriteString(" {}")
				f.Close()
			}
			if _, err := load(path, r); err == nil {
				t.Fatal("unsafe cache accepted")
			}
			if attack != "trailing JSON" {
				if err := Save(path, r); err == nil {
					t.Fatal("unsafe cache overwritten")
				}
			}
		})
	}
}

func TestConcurrentWritersNeverPublishPartialJSON(t *testing.T) {
	path, r := fixture(t)
	markers := make(map[string]bool)
	reports := make([]model.Report, 8)
	for i := range reports {
		reports[i] = r
		reports[i].Results = append([]model.Result(nil), r.Results...)
		marker := strings.Repeat(string(rune('a'+i)), 1024+i)
		markers[marker] = true
		reports[i].Results[0].Reason = marker
	}
	// Read raw publications during replacement. Load may intentionally reject
	// a concurrently unlinked inode; readers must never observe torn JSON.
	done := make(chan struct{})
	readerDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				readerDone <- nil
				return
			case <-ticker.C:
			}
			data, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				readerDone <- err
				return
			}
			var observed model.Report
			if err := json.Unmarshal(data, &observed); err != nil {
				readerDone <- err
				return
			}
			if len(observed.Results) != 1 || !markers[observed.Results[0].Reason] || observed.ConfigurationSHA256 != r.ConfigurationSHA256 {
				readerDone <- errors.New("concurrent publication mixed report data")
				return
			}
		}
	}()
	var wg sync.WaitGroup
	results := make(chan error, len(reports))
	for _, report := range reports {
		wg.Add(1)
		go func(report model.Report) { defer wg.Done(); results <- Save(path, report) }(report)
	}
	wg.Wait()
	close(done)
	if err := <-readerDone; err != nil {
		t.Fatal(err)
	}
	close(results)
	succeeded := false
	for err := range results {
		if err == nil {
			succeeded = true
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if !succeeded {
		t.Fatal("no writer published a cache")
	}
	final, err := load(path, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Results) != 1 || !markers[final.Results[0].Reason] {
		t.Fatal("final publication is not a complete candidate report")
	}
}

func TestCacheLengthLimitBeforeDecode(t *testing.T) {
	path, r := fixture(t)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxReportBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := load(path, r); err == nil {
		t.Fatal("oversized cache accepted")
	}
}

func TestTrustSourceReplacedByFIFOIsRejectedWithoutBlocking(t *testing.T) {
	path, r := fixture(t)
	source := r.Results[0].TrustSources[0].Path
	if err := Save(path, r); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(source, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := load(path, r); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as a trust file")
		}
	case <-time.After(time.Second):
		// Release a buggy blocking reader so this regression test stays bounded.
		if f, err := os.OpenFile(source, os.O_RDWR|syscall.O_NONBLOCK, 0); err == nil {
			f.Close()
		}
		t.Fatal("FIFO blocked the cache reader")
	}
}

func TestDistinctTrustFilesShareReadBudget(t *testing.T) {
	dir := t.TempDir()
	hash := sha256.Sum256([]byte("same"))
	remaining := int64(6)
	for index, name := range []string{"first.pem", "second.pem"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("same"), 0600); err != nil {
			t.Fatal(err)
		}
		source := model.TrustSource{Path: path, SHA256: hex.EncodeToString(hash[:]), Complete: true}
		err := verifySourceBudget(source, &remaining)
		if index == 0 && err != nil {
			t.Fatal(err)
		}
		if index == 1 && err == nil {
			t.Fatal("distinct sources reset total I/O budget")
		}
	}
}
