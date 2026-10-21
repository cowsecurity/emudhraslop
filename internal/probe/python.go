package probe

import (
	"context"
	_ "embed"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

//go:embed scripts/python.py
var pythonScript string

// Python checks an isolated native client with the explicitly declared CA/env.
// It does not claim to reproduce arbitrary application hooks or SSLContext code.
func Python(ctx context.Context, t model.Target, inc *incident.Incident, opts Options) model.Result {
	if t.Client == "" {
		t.Client = "stdlib"
	}
	switch t.Client {
	case "stdlib", "requests", "httpx", "botocore", "urllib3", "aiohttp":
	default:
		r := model.NewResult(t)
		r.Reason = "unsupported_python_client"
		return r
	}
	if t.Client == "requests" && t.CABundle != "" && t.CADir != "" {
		r := model.NewResult(t)
		r.Reason = "unsupported_configuration"
		return r
	}
	// These native clients do not consume proxy environment variables by default.
	// Refuse a declared proxy rather than silently testing a direct connection.
	if t.Client == "urllib3" || t.Client == "aiohttp" {
		for key, value := range t.Environment {
			if value != "" && strings.HasSuffix(strings.ToLower(key), "_proxy") && !strings.EqualFold(key, "no_proxy") {
				r := model.NewResult(t)
				r.Reason = "unsupported_proxy_configuration"
				return r
			}
		}
	}
	args := []string{"-I", "-c"}
	if t.Client == "stdlib" {
		args = []string{"-I", "-S", "-c"}
	}
	return runtimeProbe(ctx, t, inc, opts, pythonScript, args)
}
