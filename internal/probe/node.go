package probe

import (
	"context"
	_ "embed"
	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

//go:embed scripts/node.js
var nodeScript string

func Node(ctx context.Context, t model.Target, inc *incident.Incident, opts Options) model.Result {
	if t.Client == "" {
		t.Client = "tls"
	}
	if t.Client != "tls" && t.Client != "https" && t.Client != "fetch" {
		r := model.NewResult(t)
		r.Reason = "unsupported_node_client"
		r.NextAction = "Declare a tls, https, or built-in fetch context; custom dispatchers require their own adapter."
		return r
	}
	if t.Client == "fetch" && (t.CABundle != "" || t.CADir != "") {
		r := model.NewResult(t)
		r.Reason = "unsupported_node_fetch_ca_configuration"
		r.NextAction = "Built-in fetch has no per-request CA option. Declare NODE_EXTRA_CA_CERTS only if that is the actual client configuration."
		return r
	}
	if t.CADir != "" {
		r := model.NewResult(t)
		r.Reason = "unsupported_node_ca_directory"
		return r
	}
	return runtimeProbe(ctx, t, inc, opts, nodeScript, []string{"--eval"})
}
