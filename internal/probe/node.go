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
	if t.Client != "tls" && t.Client != "https" {
		r := model.NewResult(t)
		r.Reason = "unsupported_node_client"
		r.NextAction = "Declare a tls/https context; fetch and custom dispatchers need an adapter with peer-certificate attribution."
		return r
	}
	if t.CADir != "" {
		r := model.NewResult(t)
		r.Reason = "unsupported_node_ca_directory"
		return r
	}
	return runtimeProbe(ctx, t, inc, opts, nodeScript, []string{"--eval"})
}
