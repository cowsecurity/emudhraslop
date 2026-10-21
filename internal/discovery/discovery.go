// Package discovery performs bounded managed-path inventory. It never claims
// that a machine's arbitrary applications or service TLS contexts were covered.
package discovery

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/config"
	"github.com/cowsecurity/emudhraslop/internal/model"
	"github.com/cowsecurity/emudhraslop/internal/platform"
)

const maxPATHDirectories = 64

func Managed() ([]model.Target, model.Coverage) {
	coverage := model.Coverage{Scope: "managed", Complete: false,
		Exclusions: []string{"arbitrary applications, browsers, Java, Rust and Go TLS clients", "custom TLS contexts, virtual environments absent from PATH and undeclared service identities", "other containers, build stages and the host machine", "code signing, inbound server certificates and incident paths absent from the embedded manifest"}, Warnings: []string{}}
	directories := []string{"/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"}
	if runtime.GOOS == "windows" {
		directories = nil
		coverage.Exclusions = append(coverage.Exclusions, "Windows system trust stores, Windows service accounts, elevation and Windows Store aliases; only current-token native client contexts are probed")
		coverage.Warnings = append(coverage.Warnings, "Windows cache reuse is unavailable; fresh checks do not cache; uid/gid values are Unix placeholders and do not represent Windows SIDs")
	}
	paths := filepath.SplitList(os.Getenv("PATH"))
	if len(paths) > maxPATHDirectories {
		paths = paths[:maxPATHDirectories]
		coverage.Warnings = append(coverage.Warnings, "PATH discovery limit reached; declare omitted contexts explicitly")
	}
	for _, path := range paths {
		if filepath.IsAbs(path) {
			directories = append(directories, filepath.Clean(path))
		} else if path != "" {
			coverage.Warnings = append(coverage.Warnings, "relative PATH entry excluded from managed discovery")
		}
	}
	env, envErr := trustEnvironment()
	if envErr != nil {
		coverage.Warnings = append(coverage.Warnings, "unsupported trust environment prevents native probing; declare a safe explicit service context")
		env = nil
	}
	u, g := uint32(os.Geteuid()), uint32(os.Getegid())
	names := []struct{ name, kind, client string }{{"curl", "curl", "curl"}, {"openssl", "openssl", "openssl"}, {"node", "node", "tls"}, {"python3", "python", "stdlib"}, {"python", "python", "stdlib"}}
	for minor := 8; minor <= 16; minor++ {
		names = append(names, struct{ name, kind, client string }{fmt.Sprintf("python3.%d", minor), "python", "stdlib"})
	}
	seen := map[string]bool{}
	targets := []model.Target{}
	limitReached := false
	for _, dir := range directories {
		for _, candidate := range names {
			name := candidate.name
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			path := filepath.Join(dir, name)
			var info os.FileInfo
			var err error
			resolved := path
			if runtime.GOOS == "windows" {
				// Do not Stat or resolve a candidate before the no-reparse open:
				// either operation could traverse a local junction into SMB.
				if !platform.ValidPath(path) {
					continue
				}
				file, openErr := platform.OpenRead(path)
				if openErr != nil {
					if errors.Is(openErr, platform.ErrReparse) || errors.Is(openErr, platform.ErrNonlocal) {
						coverage.Warnings = append(coverage.Warnings, "reparse or indirect-volume executable path excluded; declare a direct local context")
					}
					continue
				}
				info, err = file.Stat()
				file.Close()
			} else {
				info, err = os.Stat(path)
				if err == nil {
					resolved, err = filepath.EvalSymlinks(path)
					if err != nil {
						coverage.Warnings = append(coverage.Warnings, "unresolvable managed executable excluded")
					}
				}
			}
			if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
				continue
			}

			executable, key := resolved, candidate.kind+":"+resolved
			if candidate.kind == "python" {
				if root, ok := virtualEnvironment(path); ok {
					// Python locates pyvenv.cfg from its invocation path. Resolving
					// that symlink would silently probe the base interpreter instead.
					executable = path
					key += ":venv:" + root
				}
			}
			if runtime.GOOS == "windows" {
				key = strings.ToLower(key)
				if !platform.ValidPath(resolved) || strings.Contains(strings.ToLower(resolved), `\microsoft\windowsapps\`) {
					coverage.Warnings = append(coverage.Warnings, "non-local or Windows Store execution alias excluded")
					continue
				}
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			clients := []string{candidate.client}
			if candidate.kind == "python" {
				clients = pythonClients
			} else if candidate.kind == "node" {
				clients = []string{"tls", "https", "fetch"}
			}
			for _, client := range clients {
				if len(targets) >= config.MaxTargets {
					limitReached = true
					continue
				}
				t := model.Target{ID: fmt.Sprintf("managed-%s-%s-%d", candidate.kind, client, len(targets)+1), Kind: candidate.kind, Client: client, Executable: executable, UID: &u, GID: &g, Environment: env, Source: "managed-discovery", MetadataOnly: envErr != nil}
				if env["NODE_TLS_REJECT_UNAUTHORIZED"] == "0" && t.Kind == "node" {
					t.VerificationDisabled = true
				}
				targets = append(targets, t)
			}
		}
	}
	if runtime.GOOS == "darwin" {
		if len(targets) < config.MaxTargets {
			path, client := appleExecutable()
			targets = append(targets, model.Target{ID: "managed-apple", Kind: "apple", Client: client, Executable: path, UID: &u, GID: &g, Source: "managed-discovery"})
		} else {
			limitReached = true
		}
	}
	if limitReached {
		coverage.Warnings = append(coverage.Warnings, "managed context limit reached; omitted contexts require a separate explicit scan")
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	if len(targets) == 0 {
		coverage.Warnings = append(coverage.Warnings, "no supported managed runtime executable found")
	}
	if InContainer() {
		coverage.Warnings = append(coverage.Warnings, "inventory is limited to this container filesystem and execution identity")
	}
	return targets, coverage
}

func appleExecutable() (string, string) {
	candidates := []string{}
	if executable, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(executable); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(resolved), "emudhraslop-sectrust"))
		}
	}
	candidates = append(candidates, "/usr/local/libexec/emudhraslop-sectrust")
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, "sectrust-helper"
		}
	}
	return "/usr/bin/swift", "security-framework"
}

func InContainer() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, path := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	if os.Getenv("container") != "" {
		return true
	}
	f, err := os.Open("/proc/1/cgroup")
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return false
	}
	value := string(data)
	for _, marker := range []string{"docker", "kubepods", "containerd", "libpod", "lxc"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}
