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
	payloads "github.com/chainreactors/cyber/aop/payloads"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Actions are the three verdicts a rule row or the default action can carry;
// the seam (tools/proxy, aliased in judge.go) spells the same values.
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

// Verdict is one judged request — the payload contract's wire shape
// (aop/payloads.TrafficVerdict) aliased in, so the fence's verdicts and the
// control plane's sidecar decoder cannot drift.
type Verdict = payloads.TrafficVerdict

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

// JudgeConnect judges a CONNECT tunnel against the fence's host form only
// (fork patch 31): at tunnel setup there is no method beyond CONNECT itself
// and no path, so rows match on host alone (a method/path row refines the
// decrypted inner requests, not the tunnel). A CONNECT URL is authority form
// ("host:port"), which url.Parse reads as scheme:opaque — RequestHost retries
// with a scheme prepended so the host survives. CIDR rows match literal IPs
// directly and hostnames through the cached resolver, so the full host
// vocabulary judges here too; an unmatched tunnel refuses under the allowlist
// default rather than passing unjudged. In relay mode this host-form
// pass/fail IS the fence. Shadow still records and passes.
func (s *Set) JudgeConnect(rawURL string) (Verdict, bool) {
	if s == nil || !s.Enabled {
		return Verdict{}, false
	}
	host := RequestHost(rawURL)
	for _, rule := range s.Rules {
		prefix := rule.PathPrefix
		if prefix == "" {
			prefix = "/"
		}
		if prefix == "/" && hostMatches(rule.Host, host) {
			return Verdict{Action: rule.Action, RuleID: rule.ID,
				Reason: fmt.Sprintf("命中测试范围规则 %s（%s）", rule.ID, rule.Host),
				Shadow: s.Shadow}, true
		}
	}
	return Verdict{Action: s.DefaultAction,
		Reason:        "CONNECT 未命中测试范围规则的 host 形态，按默认动作 " + s.DefaultAction,
		Shadow:        s.Shadow,
		DefaultMissed: true,
	}, true
}

// JudgeSessionConnect judges one CONNECT tunnel attributed to a session.
func (s *Store) JudgeSessionConnect(sessionID, rawURL string) (Verdict, bool) {
	s.storeMu.RLock()
	set := s.storeSets[sessionID]
	s.storeMu.RUnlock()
	return set.JudgeConnect(rawURL)
}

// HostMatches applies one host pattern to a request host with the fence's
// matching semantics — exact bare domain plus its whole subdomain tree, or a
// CIDR block against the resolved address (cached, bounded). Exported for the
// instance-wide global fence, whose domain rows must mean exactly what a
// scope-rule host column means.
func HostMatches(pattern, host string) bool {
	return hostMatches(pattern, host)
}

// RequestHost extracts the authority a raw URL names. A CONNECT URL is
// authority form ("host:port"), which url.Parse reads as scheme:opaque or
// rejects outright (a port after a digit-leading host) — retried with a
// scheme prepended so the host survives. Exported beside HostMatches for the
// same consumer.
func RequestHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err == nil {
		if host := parsed.Hostname(); host != "" {
			return host
		}
		if parsed.Host != "" || strings.Contains(rawURL, "//") {
			return ""
		}
	}
	parsed, err = url.Parse("http://" + rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
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

// Store owns the per-session table, the rotation park and the flow verdict
// registry (docs/19 E3-4): no package-level session state. The fence
// extension creates one store, Provides it, installs it for the readers that
// predate the contribution point (the proxy judge seam and the observe
// sidecar read the package functions), and uninstalls it on Close.
type Store struct {
	storeMu   sync.RWMutex
	storeSets map[string]*Set
	storeRing []string

	parkMu    sync.Mutex
	parkSets  map[string]*Set
	parkOrder []string
}

// NewStore builds an empty store.
func NewStore() *Store {
	return &Store{storeSets: map[string]*Set{}, parkSets: map[string]*Set{}}
}

// ErrNotMounted is returned by SetRules when no fence extension has installed
// a store: a registration with nowhere to go must not vanish silently.
var ErrNotMounted = fmt.Errorf("scope-rule store is not mounted (no fence extension installed)")

var installed atomic.Pointer[Store]

// Install mounts s as the tables the package functions read. Production
// callers are the fence extension's Load and Close.
func Install(s *Store) { installed.Store(s) }

// Uninstall removes the mounted store; package-function calls judge and
// record nothing afterwards.
func Uninstall() { installed.Store(nil) }

func current() *Store { return installed.Load() }

// ErrCapacity reports that the per-session table is full. The caller must
// refuse this session's turn instead of letting it run: evicting the oldest
// entry would silently unfence a live session, and skipping the registration
// would unfence this one — neither failure mode may pass without a log, and a
// rejected turn is the only outcome that keeps every session fenced.
var ErrCapacity = fmt.Errorf("scope-rule session table is full (%d live sessions); refuse the turn", maxSessions)

// SetRules replaces the rule set of one session from its manifest JSON. An
// invalid set is an error and leaves the previous set untouched; a session
// that stops sending the extension keeps its last set (the control plane
// re-sends disabled drafts every turn precisely to keep this honest). A NEW
// session beyond the table's capacity is ErrCapacity, not an eviction: the
// oldest live session's fence must never be dropped behind its back.
func (s *Store) SetRules(sessionID string, raw []byte) error {
	set, err := Parse(raw)
	if err != nil {
		return err
	}
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	if _, exists := s.storeSets[sessionID]; !exists {
		if len(s.storeRing) >= maxSessions {
			return ErrCapacity
		}
		s.storeRing = append(s.storeRing, sessionID)
	}
	s.storeSets[sessionID] = set
	return nil
}

// DropSession forgets one session's rule set. Called when the session closes,
// so the table holds only live sessions and capacity is never exhausted by
// stale ids. Unknown ids are a no-op.
func (s *Store) DropSession(sessionID string) {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	if _, exists := s.storeSets[sessionID]; !exists {
		return
	}
	delete(s.storeSets, sessionID)
	for i, id := range s.storeRing {
		if id == sessionID {
			s.storeRing = append(s.storeRing[:i], s.storeRing[i+1:]...)
			break
		}
	}
}

// The rotation park holds the sets of sessions closed by a rotation (/clear,
// /compact, resume) for one continuation hop. The agent rotates by closing
// the old session before opening its continuation, so the child's
// SessionStart finds the parent already gone from the live table (docs/19
// appendix E2-2): without the park, inheritance silently misses and the
// child runs a turn unfenced. The park is bounded; its oldest entry is
// forgotten when a session closes by rotation and never opens a child.
// ParkSession moves one session's set out of the live table into the rotation
// park. Unknown ids are a no-op.
func (s *Store) ParkSession(sessionID string) {
	s.storeMu.Lock()
	set, exists := s.storeSets[sessionID]
	if exists {
		delete(s.storeSets, sessionID)
		for i, id := range s.storeRing {
			if id == sessionID {
				s.storeRing = append(s.storeRing[:i], s.storeRing[i+1:]...)
				break
			}
		}
	}
	s.storeMu.Unlock()
	if !exists {
		return
	}
	s.parkMu.Lock()
	defer s.parkMu.Unlock()
	if _, exists := s.parkSets[sessionID]; !exists {
		s.parkOrder = append(s.parkOrder, sessionID)
	}
	s.parkSets[sessionID] = set
	if len(s.parkOrder) > maxSessions {
		oldest := s.parkOrder[0]
		s.parkOrder = s.parkOrder[1:]
		delete(s.parkSets, oldest)
	}
}

// TakeParkedSession removes and returns one parked set. ok is false when the
// id has no parked set.
func (s *Store) TakeParkedSession(sessionID string) (set *Set, ok bool) {
	s.parkMu.Lock()
	defer s.parkMu.Unlock()
	set, ok = s.parkSets[sessionID]
	if ok {
		delete(s.parkSets, sessionID)
		for i, id := range s.parkOrder {
			if id == sessionID {
				s.parkOrder = append(s.parkOrder[:i], s.parkOrder[i+1:]...)
				break
			}
		}
	}
	return set, ok
}

// JudgeSession judges one request attributed to a session. judged is false
// when the session has no enabled set.
func (s *Store) JudgeSession(sessionID, method, rawURL string) (Verdict, bool) {
	s.storeMu.RLock()
	set := s.storeSets[sessionID]
	s.storeMu.RUnlock()
	return set.Judge(method, rawURL)
}

// InheritSessionRules copies the parent session's rule set to the child
// session's slot (fork patch 33). The agent's own subagent tool opens child
// sessions with fresh ids that never see a RunTurnRequest, so without this
// their requests judge nothing. The copy shares the parent's parsed set — it
// is read-only after Parse — and the next turn re-registers the root's newest
// set; a child that lives across a rule edit keeps the set it was born with,
// which is the honest reading of "registered for that session". A parent with
// no registered set inherits nothing. A child beyond the table's capacity is
// ErrCapacity: silently skipping would open the child session unfenced, so
// the caller must fail the child's creation instead.
func (s *Store) InheritSessionRules(parentID, childID string) error {
	if parentID == "" || childID == "" || parentID == childID {
		return nil
	}
	s.storeMu.RLock()
	set := s.storeSets[parentID]
	s.storeMu.RUnlock()
	if set == nil {
		// The parent may have closed a rotation hop ahead of this open
		// (docs/19 appendix E2-2); its set is in the rotation park.
		parked, ok := s.TakeParkedSession(parentID)
		if !ok {
			return nil
		}
		set = parked
	}
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	if _, exists := s.storeSets[childID]; !exists {
		if len(s.storeRing) >= maxSessions {
			return ErrCapacity
		}
		s.storeRing = append(s.storeRing, childID)
	}
	s.storeSets[childID] = set
	return nil
}

// The package functions below are the read seam for the callers that hold no
// store reference (the request decorators, the session hooks). They delegate
// to the store the fence extension installed; without one, sessions judge
// nothing — the no-fence composition. The flow-verdict registry is not here:
// the proxy seam owns it (tools/proxy, aliased in judge.go).

// SetRules replaces one session's set from its manifest JSON on the mounted
// store. Unmounted, it fails: a skipped registration would run the session
// unfenced.
func SetRules(sessionID string, raw []byte) error {
	if s := current(); s != nil {
		return s.SetRules(sessionID, raw)
	}
	return ErrNotMounted
}

// DropSession forgets one session's set on the mounted store.
func DropSession(sessionID string) {
	if s := current(); s != nil {
		s.DropSession(sessionID)
	}
}

// ParkSession parks one session's set for a rotation hop on the mounted store.
func ParkSession(sessionID string) {
	if s := current(); s != nil {
		s.ParkSession(sessionID)
	}
}

// JudgeSession judges one request on the mounted store; judged is false when
// no store is mounted (the no-fence composition judges nothing).
func JudgeSession(sessionID, method, rawURL string) (Verdict, bool) {
	if s := current(); s != nil {
		return s.JudgeSession(sessionID, method, rawURL)
	}
	return Verdict{}, false
}

// JudgeSessionConnect judges one CONNECT request on the mounted store.
func JudgeSessionConnect(sessionID, rawURL string) (Verdict, bool) {
	if s := current(); s != nil {
		return s.JudgeSessionConnect(sessionID, rawURL)
	}
	return Verdict{}, false
}

// InheritSessionRules copies the parent's set to the child on the mounted
// store. Unmounted, it is a no-op: no store means no fence extension, whose
// Load subscribes the inheritance hook in the first place.
func InheritSessionRules(parentID, childID string) error {
	if s := current(); s != nil {
		return s.InheritSessionRules(parentID, childID)
	}
	return nil
}
