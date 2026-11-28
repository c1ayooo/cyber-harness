package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/chainreactors/cyber/core/telemetry"
	types "github.com/chainreactors/cyber/core/types"
)

// probe runs one connectivity test with a caller-chosen budget; Probe is its
// fixed-budget wrapper. Two budgets exist, and the split between them is the
// whole point:
//
//   - startupLLMProbeTimeout (5s) bounds the fast, non-blocking probe used when
//     a live configuration is being replaced (Update). Replacing a live
//     provider is degradation-safe: a failed probe keeps the previous client,
//     so it stays on the short liveness window.
//   - Activating the first provider is not degradation-safe: the caller has
//     nothing to fall back on. Activation is the one probe that decides
//     whether this node gets a provider at all — failing it makes the caller
//     discard the candidate and keep the provider-disabled profile, so every
//     session then fails with "agent provider is nil". A gateway whose first
//     token takes several seconds is slow, not misconfigured, and rejecting it
//     left the node provider-disabled for every session. Give activation the
//     same budget as a real request (llmProbeTimeout); slow-but-working
//     gateways take 3-7s for the first token.
func probe(ctx context.Context, provCfg ProviderConfig, logger telemetry.Logger, timeout time.Duration) Health {
	if logger == nil {
		logger = telemetry.NopLogger()
	}
	health := Health{State: HealthConfigured, CheckedAt: time.Now()}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	result, err := TestLLM(probeCtx, &types.LLMProbeRequest{
		Provider: provCfg.Provider,
		BaseUrl:  provCfg.BaseURL,
		ApiKey:   provCfg.APIKey,
		Model:    provCfg.Model,
		Proxy:    provCfg.Proxy,
	}, "")
	if err != nil {
		health.State = HealthFailed
		health.Error = err.Error()
		logger.Warnf("%s", telemetry.StartupLine("fail", "llm", fmt.Sprintf("%s · %s", llmConfigLabel(provCfg.Provider, provCfg.Model), err.Error())))
		return health
	}
	health.LatencyMs = result.LatencyMs
	if !result.Ok {
		health.State = HealthFailed
		health.Error = result.Error
		logger.Warnf("%s", telemetry.StartupLine("fail", "llm", fmt.Sprintf("%s · %dms · %s", llmConfigLabel(result.Provider, result.Model), result.LatencyMs, result.Error)))
		return health
	}

	health.State = HealthReady
	logger.Infof("%s", telemetry.StartupOK("llm", fmt.Sprintf("%s · %dms", llmConfigLabel(result.Provider, result.Model), result.LatencyMs)))
	return health
}
