// Package scoperules is the shared state for the control plane's
// machine-matchable test range (project scope_rules): the per-session rule
// sets the agent registers from the fork's per-turn extension, the verdict
// registry the proxy writes and the observe extension consumes as the flow
// verdict sidecar.
//
// The rules themselves are the control plane's manifest schema
// (project.json "scope_rules"); this package parses them defensively and is
// the single judging authority, so the agent session, the guardrail runtime
// and the proxy agree on one implementation. An invalid or absent set means
// "not judged" — never a guessed verdict.
package scoperules

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Actions are the three verdicts a rule row or the default action can carry.
const (
	ActionRecord = "record"
	ActionReview = "review"
	ActionBlock  = "block"
)

// maxSessions bounds the per-session rule sets and the verdict registry, so a
// long-lived scan process cannot grow them without limit. Session stores are
// overwritten on every turn, and verdicts are consumed by the observe
// extension; both are hot-path bounded caches, not ledgers.
const (
	maxSessions = 64
	maxVerdicts = 4096
)

// Rule is one manifest row. Method is "*" or verbs joined by "|"; Host is "*",
// an exact hostname, "*.example.com" (every subdomain), or a CIDR block
// ("10.0.0.0/8", matched against the target's resolved address); PathPrefix is
// a literal URL path prefix ("/" = everything).
type Rule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
}

// Set is one parsed project rule set. Shadow means judge and record but
// always forward: the verdict travels to the control plane while no request
// is held or refused.
type Set struct {
	Enabled       bool   `json:"enabled"`
	DefaultAction string `json:"default_action"`
	Shadow        bool   `json:"shadow"`
	Rules         []Rule `json:"rules"`
}

// Verdict is one judged request.
type Verdict struct {
	Action string `json:"action"`
	RuleID string `json:"rule_id,omitempty"`
	Reason string `json:"reason,omitempty"`
	Shadow bool   `json:"shadow,omitempty"`
	// DefaultMissed marks a fallback verdict (no rule row matched, fork patch
	// 30): the control plane routes it to the asset-pending flow instead of
	// reading it as a verdict the operator wrote by hand. Absent on a hit, so
	// old control planes ignore the field entirely.
	DefaultMissed bool `json:"default_missed,omitempty"`
}

// maxRules mirrors the control plane's rule-table cap (project MaxScopeRules,
// raised to 512 with the allowlist fence): the two sides must accept the same
// set, or a saved manifest would fail to register on the node.
const maxRules = 512

var validAction = map[string]bool{ActionRecord: true, ActionReview: true, ActionBlock: true}

// Parse decodes and validates one manifest rule set. The control plane is the
// authority for the schema; this only refuses sets it cannot judge honestly.
func Parse(raw []byte) (*Set, error) {
	var set Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("scope rules: %w", err)
	}
	if !validAction[set.DefaultAction] {
		return nil, fmt.Errorf("scope rules: default_action %q is not record/review/block", set.DefaultAction)
	}
	if len(set.Rules) > maxRules {
		return nil, fmt.Errorf("scope rules: more than %d rows", maxRules)
	}
	for i := range set.Rules {
		rule := &set.Rules[i]
		rule.Method = strings.ToUpper(strings.TrimSpace(rule.Method))
		rule.Host = strings.ToLower(strings.TrimSpace(rule.Host))
		rule.PathPrefix = strings.TrimSpace(rule.PathPrefix)
		if rule.PathPrefix != "" && !strings.HasPrefix(rule.PathPrefix, "/") {
			return nil, fmt.Errorf("scope rules: rule %q path_prefix must start with /", rule.ID)
		}
		if !validAction[rule.Action] {
			return nil, fmt.Errorf("scope rules: rule %q action %q is not record/review/block", rule.ID, rule.Action)
		}
		if rule.Host == "" {
			return nil, fmt.Errorf("scope rules: rule %q has no host", rule.ID)
		}
	}
	return &set, nil
}

// Judge applies the set top-down: the first matching row wins, a miss falls to
// the default action. judged is false for a disabled set (or one whose request
// cannot be parsed) — the caller must not invent a verdict.
func (s *Set) Judge(method, rawURL string) (Verdict, bool) {
	if s == nil || !s.Enabled {
		return Verdict{}, false
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	host, path := requestTarget(rawURL)
	for _, rule := range s.Rules {
		if ruleMatches(rule, method, host, path) {
			return Verdict{Action: rule.Action, RuleID: rule.ID,
				Reason: fmt.Sprintf("命中测试范围规则 %s（%s %s%s）", rule.ID, rule.Method, rule.Host, rule.PathPrefix),
				Shadow: s.Shadow}, true
		}
	}
	return Verdict{Action: s.DefaultAction,
		Reason:        "未命中测试范围规则，按默认动作 " + s.DefaultAction,
		Shadow:        s.Shadow,
		DefaultMissed: true,
	}, true
}

func ruleMatches(rule Rule, method, host, path string) bool {
	if !methodMatches(rule.Method, method) {
		return false
	}
	if !hostMatches(rule.Host, host) {
		return false
	}
	prefix := rule.PathPrefix
	if prefix == "" {
		prefix = "/"
	}
	return strings.HasPrefix(path, prefix)
}

func methodMatches(pattern, method string) bool {
	pattern = strings.ToUpper(strings.TrimSpace(pattern))
	if pattern == "" || pattern == "*" {
		return true
	}
	for _, token := range strings.Split(pattern, "|") {
		if strings.TrimSpace(token) == method {
			return true
		}
	}
	return false
}

func hostMatches(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if pattern == "*" {
		return true
	}
	// CIDR rows (fork patch 23a, docs/04): "10.0.0.0/8" matches the target's
	// resolved address — an IP-literal host is matched directly, a hostname is
	// resolved (cached, bounded) first. The control plane's schema validates
	// the same shapes (project/scope_rules.go), so the two sides stay in lock
	// step; an unparseable value falls back to the exact-hostname comparison,
	// which can only miss — a version-mismatched rule set must never over-fence.
	if strings.Contains(pattern, "/") {
		return cidrHostMatches(pattern, host)
	}
	// One domain row covers the bare host and every subdomain (fork patch 26,
	// the allowlist fence). The legacy "*." and "." spellings normalize onto
	// the same comparison — the control plane stores the bare domain, so a row
	// written "*.example.com" and one written "example.com" match the identical
	// set. The base-host exclusion the wildcard forms used to carry is gone:
	// an operator fencing a domain fences the domain itself.
	base := strings.TrimPrefix(strings.TrimPrefix(pattern, "*."), ".")
	return host == base || strings.HasSuffix(host, "."+base)
}

// cidrHostMatches matches one CIDR row against the request host. Failure at
// every stage (bad prefix, unresolvable hostname, timeout) is a miss, never an
// error verdict: fencing is a safety property, and blocking on infrastructure
// noise would fence the operator out of their own range.
func cidrHostMatches(pattern, host string) bool {
	prefix, err := netip.ParsePrefix(pattern)
	if err != nil {
		// Unknown shape: exact-hostname fallback (the control plane normalizes
		// CIDR rows before storing, so this line is defensive only).
		return host == pattern
	}
	prefix = prefix.Masked()
	if addr, err := netip.ParseAddr(host); err == nil {
		return prefix.Contains(addr.WithZone("").Unmap())
	}
	for _, addr := range resolveHost(host) {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// The DNS side of the CIDR branch runs on the proxy data path, so lookups are
// cached and bounded: one entry per hostname (positive and negative results
// alike), oldest entries evicted at the cap, every entry expiring on its own.
// lookupHost is a variable for tests; production uses net.DefaultResolver.
var (
	dnsMu      sync.Mutex
	dnsCache   = map[string]dnsEntry{}
	dnsRing    []string
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
)

const (
	dnsTTL     = 5 * time.Minute
	dnsTimeout = 2 * time.Second
	dnsMax     = 512
)

type dnsEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

func resolveHost(host string) []netip.Addr {
	dnsMu.Lock()
	if e, ok := dnsCache[host]; ok && time.Now().Before(e.expires) {
		dnsMu.Unlock()
		return e.addrs
	}
	dnsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	names, err := lookupHost(ctx, host)
	var addrs []netip.Addr
	if err == nil {
		for _, name := range names {
			if addr, aerr := netip.ParseAddr(name); aerr == nil {
				addrs = append(addrs, addr.WithZone("").Unmap())
			}
		}
	}
	// A failed or empty resolution is cached too: an unreachable target must
	// not turn every request into a fresh timeout.
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if _, exists := dnsCache[host]; !exists {
		dnsRing = append(dnsRing, host)
		if len(dnsRing) > dnsMax {
			delete(dnsCache, dnsRing[0])
			dnsRing = dnsRing[1:]
		}
	}
	dnsCache[host] = dnsEntry{addrs: addrs, expires: time.Now().Add(dnsTTL)}
	return addrs
}

func requestTarget(rawURL string) (host, path string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "/"
	}
	return parsed.Hostname(), parsed.RequestURI()
}

// ---------------------------------------------------------------------------
// session store: the agent registers one set per session on every turn.
// ---------------------------------------------------------------------------

var (
	storeMu   sync.RWMutex
	storeSets = map[string]*Set{}
	storeRing []string
)

// SetRules replaces the rule set of one session from its manifest JSON. An
// invalid set is an error and leaves the previous set untouched; a session
// that stops sending the extension keeps its last set (the control plane
// re-sends disabled drafts every turn precisely to keep this honest).
func SetRules(sessionID string, raw []byte) error {
	set, err := Parse(raw)
	if err != nil {
		return err
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if _, exists := storeSets[sessionID]; !exists {
		storeRing = append(storeRing, sessionID)
		if len(storeRing) > maxSessions {
			delete(storeSets, storeRing[0])
			storeRing = storeRing[1:]
		}
	}
	storeSets[sessionID] = set
	return nil
}

// JudgeSession judges one request attributed to a session. judged is false
// when the session has no enabled set.
func JudgeSession(sessionID, method, rawURL string) (Verdict, bool) {
	storeMu.RLock()
	set := storeSets[sessionID]
	storeMu.RUnlock()
	return set.Judge(method, rawURL)
}

// ---------------------------------------------------------------------------
// verdict registry: one judged request -> one flow sidecar, keyed by proxy
// flow id (an operation covers many requests, so it cannot key this).
// ---------------------------------------------------------------------------

var (
	verdictMu     sync.Mutex
	verdictOrder  []string
	verdictByFlow = map[string]Verdict{}
)

// RecordVerdict stores the verdict of one judged request for the observe
// extension to attach as the flow's TrafficVerdict sidecar.
func RecordVerdict(flowID string, verdict Verdict) {
	if flowID == "" {
		return
	}
	verdictMu.Lock()
	defer verdictMu.Unlock()
	if _, exists := verdictByFlow[flowID]; !exists {
		verdictOrder = append(verdictOrder, flowID)
		if len(verdictOrder) > maxVerdicts {
			delete(verdictByFlow, verdictOrder[0])
			verdictOrder = verdictOrder[1:]
		}
	}
	verdictByFlow[flowID] = verdict
}

// TakeVerdict consumes the verdict stored for one flow id.
func TakeVerdict(flowID string) (Verdict, bool) {
	verdictMu.Lock()
	defer verdictMu.Unlock()
	verdict, ok := verdictByFlow[flowID]
	if ok {
		delete(verdictByFlow, flowID)
	}
	return verdict, ok
}
