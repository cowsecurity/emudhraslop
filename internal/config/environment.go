package config

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/run"
)

// ValidateEnvironment accepts only trust configuration. It never returns a
// supplied value, which may contain credentials even when its key looks safe.
func ValidateEnvironment(env map[string]string) error {
	if len(env) > 24 {
		return errors.New("too many trust environment entries")
	}
	for key, value := range env {
		if !run.AllowedEnvironment(key) || len(value) > 8192 || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("unsupported trust environment setting")
		}
		switch key {
		case "NODE_OPTIONS":
			for _, flag := range strings.Fields(value) {
				switch flag {
				case "--use-system-ca", "--use-bundled-ca", "--use-openssl-ca", "--no-use-system-ca", "--no-use-bundled-ca", "--no-use-openssl-ca":
				default:
					return errors.New("NODE_OPTIONS contains unsupported execution options")
				}
			}
		case "NODE_TLS_REJECT_UNAUTHORIZED":
			if value != "0" && value != "1" {
				return errors.New("invalid TLS verification setting")
			}
		case "NODE_USE_SYSTEM_CA":
			if value != "0" && value != "1" {
				return errors.New("invalid system CA setting")
			}
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy":
			if value == "" {
				continue
			}
			u, err := url.Parse(value)
			if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
				return errors.New("proxy configuration contains unsupported credentials or URL components")
			}
			switch u.Scheme {
			case "http", "https", "socks5", "socks5h":
			default:
				return errors.New("unsupported proxy scheme")
			}
		case "NO_PROXY", "no_proxy":
			if strings.ContainsAny(value, "/@?#\\\t ") {
				return errors.New("unsupported proxy exclusion setting")
			}
		case "SSL_CERT_DIR":
			for _, path := range filepath.SplitList(value) {
				if path != "" && !validPath(path) {
					return errors.New("trust directory must use absolute paths")
				}
			}
		default:
			if value != "" && !validPath(value) {
				return errors.New("trust bundle must use an absolute path")
			}
		}
	}
	return nil
}
