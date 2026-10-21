package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/config"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/platform"
	"github.com/cowsecurity/emudhraslop/internal/run"
)

var pythonClients = []string{"stdlib", "requests", "httpx", "botocore", "urllib3", "aiohttp"}

// Project inspects only the selected directory and its conventional direct
// virtual-environment children. It does not import packages, execute programs,
// inspect process environments or recursively search a filesystem.
func Project(path string) ([]model.Target, model.Coverage, error) {
	coverage := model.Coverage{Scope: "project-discovery", Complete: false,
		Exclusions: []string{"Only the selected directory and its .venv, venv and env children are inspected.", "Application TLS overrides, other environments and custom client objects are not assessed."},
		Warnings:   []string{}}
	if path == "" || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
		return nil, coverage, errors.New("invalid project directory")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || !platform.ValidPath(absolute) {
		return nil, coverage, errors.New("invalid project directory")
	}
	info, err := inspect(absolute)
	if err != nil || !info.IsDir() {
		return nil, coverage, errors.New("project directory is unavailable or unsupported")
	}
	environment, envErr := trustEnvironment()
	if envErr != nil {
		coverage.Warnings = append(coverage.Warnings, "unsupported trust environment prevents project probing; declare a safe explicit client context")
	}
	targets := []model.Target{}
	seen := map[string]bool{}
	for _, root := range []string{absolute, filepath.Join(absolute, ".venv"), filepath.Join(absolute, "venv"), filepath.Join(absolute, "env")} {
		marker := filepath.Join(root, "pyvenv.cfg")
		cfg, err := inspect(marker)
		if err != nil {
			// A missing conventional child is normal. Windows intentionally
			// hides filesystem error details, so retain a bounded generic warning.
			if !os.IsNotExist(err) {
				coverage.Warnings = append(coverage.Warnings, "a candidate virtual environment could not be inspected")
			}
			continue
		}
		if !cfg.Mode().IsRegular() {
			coverage.Warnings = append(coverage.Warnings, "a candidate pyvenv.cfg is not a regular file")
			continue
		}
		identity, err := canonicalDirectory(root)
		if err != nil {
			coverage.Warnings = append(coverage.Warnings, "a virtual-environment directory could not be resolved")
			continue
		}
		if seen[identity] {
			continue
		}
		seen[identity] = true
		executable, available := projectPython(root)
		if !available {
			coverage.Warnings = append(coverage.Warnings, "a recognized virtual environment has no readable supported Python executable")
		}
		sum := sha256.Sum256([]byte(identity))
		uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
		for _, client := range pythonClients {
			targets = append(targets, model.Target{ID: "p-" + hex.EncodeToString(sum[:]) + "-" + client,
				Kind: "python", Client: client, Executable: executable, UID: &uid, GID: &gid,
				Environment: environment, Source: "project-discovery", MetadataOnly: !available || envErr != nil})
		}
	}
	if len(targets) == 0 {
		coverage.Warnings = append(coverage.Warnings, "no Python virtual environment found; declare other client contexts with a service manifest")
	}
	return targets, coverage, nil
}

func projectPython(root string) (string, bool) {
	names := []string{filepath.Join(root, "bin", "python3"), filepath.Join(root, "bin", "python")}
	if runtime.GOOS == "windows" {
		names = []string{filepath.Join(root, "Scripts", "python.exe")}
	}
	for _, path := range names {
		info, err := inspect(path)
		if err == nil && info.Mode().IsRegular() && (runtime.GOOS == "windows" || info.Mode().Perm()&0111 != 0) {
			return path, true
		}
	}
	return names[len(names)-1], false
}

// virtualEnvironment returns a canonical context identity without resolving the
// executable's invocation path. Both locations are recognized by Python.
func virtualEnvironment(executable string) (string, bool) {
	directory := filepath.Dir(executable)
	for _, root := range []string{directory, filepath.Dir(directory)} {
		info, err := inspect(filepath.Join(root, "pyvenv.cfg"))
		if err == nil && info.Mode().IsRegular() {
			identity, err := canonicalDirectory(root)
			return identity, err == nil
		}
	}
	return "", false
}

func canonicalDirectory(path string) (string, error) {
	if runtime.GOOS == "windows" {
		// inspect has already passed the kernel no-reparse boundary. Never
		// use EvalSymlinks/Stat first on Windows; that could traverse to SMB.
		return strings.ToLower(path), nil
	}
	return filepath.EvalSymlinks(path)
}

func inspect(path string) (os.FileInfo, error) {
	if !platform.ValidPath(path) {
		return nil, errors.New("unsupported discovery path")
	}
	file, err := platform.OpenRead(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func trustEnvironment() (map[string]string, error) {
	environment := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		if ok && run.AllowedEnvironment(key) {
			environment[key] = value
		}
	}
	if err := config.ValidateEnvironment(environment); err != nil {
		return nil, err
	}
	return environment, nil
}
