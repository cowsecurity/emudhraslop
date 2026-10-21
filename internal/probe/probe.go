package probe

import (
	"context"
	"github.com/cowsecurity/emudhraslop/internal/incident"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

func Check(ctx context.Context, t model.Target, in *incident.Incident, opts Options) model.Result {
	r := model.NewResult(t)
	if t.VerificationDisabled {
		r.Status = model.Affected
		r.Reason = "tls_verification_disabled"
		r.NextAction = "Enable certificate and hostname verification, then check again."
		return r
	}
	if t.MetadataOnly {
		r.Reason = "unsupported_or_incomplete_context"
		r.NextAction = "Declare a supported client and its effective trust configuration."
		return r
	}
	if ctx.Err() != nil {
		r.Reason = "scan_deadline"
		r.NextAction = "Check this context with a longer scan deadline."
		return r
	}
	switch t.Kind {
	case "python":
		return Python(ctx, t, in, opts)
	case "node":
		return Node(ctx, t, in, opts)
	case "curl":
		return Curl(ctx, t, in, opts)
	case "openssl":
		return OpenSSL(ctx, t, in, opts)
	case "apple":
		return Apple(ctx, t, in, opts)
	default:
		r.Reason = "unsupported_runtime"
		r.NextAction = "Assess this application's actual TLS client and trust policy separately."
		return r
	}
}
