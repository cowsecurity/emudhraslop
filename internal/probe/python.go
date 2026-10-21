package probe

import (
	"context"
	_ "embed"
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
	case "stdlib", "requests", "httpx", "botocore":
	default:
		r := model.NewResult(t)
		r.Reason = "unsupported_python_client"
		return r
	}
	args := []string{"-I", "-c"}
	if t.Client == "stdlib" {
		args = []string{"-I", "-S", "-c"}
	}
	return runtimeProbe(ctx, t, inc, opts, pythonScript, args)
}
