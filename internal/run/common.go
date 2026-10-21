package run

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"time"
)

var ErrRootDenied = errors.New("root probes require --allow-root-probes or an explicit non-root uid/gid")
var ErrOutputLimit = errors.New("subprocess output limit exceeded")

type Options struct {
	Timeout   time.Duration
	MaxOutput int
	AllowRoot bool
}
type Output struct {
	Stdout, Stderr []byte
	ExitCode       int
}

type capped struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (w *capped) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.buffer.Len() {
		w.exceeded = true
		return 0, ErrOutputLimit
	}
	return w.buffer.Write(p)
}

// No preload hooks or authenticated proxies may cross the execution boundary.
// Trust flags are preserved; unsupported runtime customization stays unknown.
func validateEnvironment(key, value string) error {
	if !AllowedEnvironment(key) || len(value) > 16384 || strings.ContainsAny(value, "\x00\n\r") {
		return errors.New("unsupported trust environment")
	}
	switch key {
	case "NODE_OPTIONS":
		for _, flag := range strings.Fields(value) {
			if flag != "--use-system-ca" && flag != "--use-bundled-ca" && flag != "--use-openssl-ca" {
				return errors.New("unsupported Node runtime option")
			}
		}
	case "NODE_USE_SYSTEM_CA", "NODE_TLS_REJECT_UNAUTHORIZED":
		if value != "0" && value != "1" {
			return errors.New("unsupported Node trust setting")
		}
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy":
		if value == "" {
			return nil
		}
		u, err := url.Parse(value)
		if err != nil || u.User != nil || u.Hostname() == "" || u.Fragment != "" || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
			return errors.New("unsupported or authenticated proxy configuration")
		}
		switch u.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return errors.New("unsupported proxy protocol")
		}
	}
	return nil
}

func AllowedEnvironment(key string) bool {
	switch key {
	case "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_USE_SYSTEM_CA", "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy":
		return true
	}
	return false
}
