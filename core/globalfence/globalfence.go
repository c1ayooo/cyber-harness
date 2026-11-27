// Package globalfence is the node-side state for the control plane's
// instance-wide red lines (4zrcin spec #1 工单3): command patterns that may
// never execute and domains that may never be reached, on every project and
// every node the instance drives. The set rides every turn as the
// 4zrcin.GlobalFence fork extension and registers per session, exactly like
// the project scope rules it sits above — a restarted host picks the newest
// payload up on the next turn instead of a stale push-once copy.
//
// The lists are deny-lists over the allowlist fence: a global hit wins before
// the project fence is consulted, so a project that allowlists gov.cn still
// cannot reach it. An absent or disabled list fences nothing.
package globalfence

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/chainreactors/cyber/core/scoperules"
)

// Actions for a command rule: deny refuses outright, review holds the call
// on the ordinary approval lifecycle.
const (
	ActionDeny   = "deny"
	ActionReview = "review"
)

var validAction = map[string]bool{ActionDeny: true, ActionReview: true}

// CommandRule is one never-execute (or always-ask) pattern. The compiled form
// lives beside it after Parse; the JSON shape is the control plane's wire
// contract.
type CommandRule struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Desc    string `json:"desc,omitempty"`
	Action  string `json:"action"`

	re *regexp.Regexp
}

// DomainRule is one never-reach identity: a bare domain (the domain and its
// whole subdomain tree), or a CIDR block matched against the target's
// resolved address — the same shapes and matching semantics as the project
// fence's host column, so the two lists cannot disagree about what a row
// means.
type DomainRule struct {
	ID   string `json:"id"`
	Host string `json:"host"`
}

// Set is one parsed instance fence. The switches are honest states, not
// convenience flags: a disabled list keeps its rows but judges nothing, and
// flipping it back on needs no retype.
type Set struct {
	EnabledCommands bool          `json:"enabled_commands"`
	Commands        []CommandRule `json:"commands,omitempty"`
	EnabledDomains  bool          `json:"enabled_domains"`
	Domains         []DomainRule  `json:"domains,omitempty"`
	// EnabledAllowDomains gates the default-allow list (fork patch 37):
	// infrastructure names — DNS/DoH endpoints, passive intel sources — the
	// executor may always reach, on every project the instance drives. The
	// deny list still wins: a red line refuses even when the name is on this
	// list, because the fence's promise is about the target range, not about
	// the operator's own infrastructure.
	EnabledAllowDomains bool         `json:"enabled_allow_domains"`
	AllowDomains        []DomainRule `json:"allow_domains,omitempty"`
}

// Parse decodes and validates one instance fence. Every pattern must compile
// (a pattern that fails at match time would silently stop fencing) and every
// action must be deny or review.
func Parse(raw []byte) (*Set, error) {
	set := new(Set)
	if err := json.Unmarshal(raw, set); err != nil {
		return nil, fmt.Errorf("global fence: %w", err)
	}
	for i := range set.Commands {
		rule := &set.Commands[i]
		re, cerr := regexp.Compile(rule.Pattern)
		if cerr != nil {
			return nil, &InvalidSetError{ID: rule.ID, Reason: "pattern 无法编译：" + cerr.Error()}
		}
		if !validAction[rule.Action] {
			return nil, &InvalidSetError{ID: rule.ID, Reason: "action 只能是 deny 或 review"}
		}
		rule.re = re
	}
	for _, d := range set.Domains {
		if !hostShapeOK(d.Host) {
			return nil, &InvalidSetError{ID: d.ID, Reason: "host 只能是域名（含裸域与子域树）或 CIDR 网段"}
		}
	}
	return set, nil
}

// hostShapeOK accepts the same host shapes the control plane stores for the
// project fence: "*", a bare hostname (the row covers its subdomain tree), or
// a CIDR prefix. The control plane is the schema authority; this only refuses
// rows the matcher would never honestly evaluate.
func hostShapeOK(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(host) > 253 {
		return false
	}
	if host == "*" {
		return true
	}
	if strings.Contains(host, "/") {
		_, err := netip.ParsePrefix(host)
		return err == nil
	}
	body := strings.TrimPrefix(strings.TrimPrefix(host, "*."), ".")
	if body == "" || strings.Contains(body, "*") {
		return false
	}
	for _, label := range strings.Split(body, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// InvalidSetError names the row that failed, so a mis-typed red line is one
// log line away from a fix instead of a silent hole.
type InvalidSetError struct {
	ID     string
	Reason string
}

func (e *InvalidSetError) Error() string { return "global fence 规则 " + e.ID + "：" + e.Reason }

// ---------------------------------------------------------------------------
// session store: the agent registers one set per session on every turn.
// ---------------------------------------------------------------------------

var (
	storeMu   sync.RWMutex
	storeSets = map[string]*Set{}
	storeRing []string
)

// ErrCapacity reports that the per-session fence table is full. The caller
// must refuse this session's turn instead of letting it run: evicting the
// oldest entry would silently unfence a live session, and skipping the
// registration would unfence this one.
var ErrCapacity = fmt.Errorf("global fence session table is full (%d live sessions); refuse the turn", maxSessions)

const maxSessions = 64

// SetRules replaces one session's instance fence. An invalid set is an error
// and leaves the previous set in force; a session that stops sending the
// extension keeps its last set (the control plane re-sends the disabled state
// every turn, which is how a fence gets turned off). A NEW session beyond the
// table's capacity is ErrCapacity, not an eviction: the oldest live session's
// fence must never be dropped behind its back.
func SetRules(sessionID string, raw []byte) error {
	set, err := Parse(raw)
	if err != nil {
		return err
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if _, exists := storeSets[sessionID]; !exists {
		if len(storeRing) >= maxSessions {
			return ErrCapacity
		}
		storeRing = append(storeRing, sessionID)
	}
	storeSets[sessionID] = set
	return nil
}

// DropSession forgets one session's instance fence. Called when the session
// closes, so the table holds only live sessions. Unknown ids are a no-op.
func DropSession(sessionID string) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if _, exists := storeSets[sessionID]; !exists {
		return
	}
	delete(storeSets, sessionID)
	for i, id := range storeRing {
		if id == sessionID {
			storeRing = append(storeRing[:i], storeRing[i+1:]...)
			break
		}
	}
}

// JudgeCommand matches one command's text against the session's enabled
// pattern list. hit is false when nothing matches — including when the list
// is disabled or the session never registered one.
func JudgeCommand(sessionID, text string) (CommandRule, bool) {
	storeMu.RLock()
	set := storeSets[sessionID]
	storeMu.RUnlock()
	if set == nil || !set.EnabledCommands || text == "" {
		return CommandRule{}, false
	}
	for _, rule := range set.Commands {
		if rule.re != nil && rule.re.MatchString(text) {
			return rule, true
		}
	}
	return CommandRule{}, false
}

// DomainHit reports the first deny-list entry the host (or its resolved
// address) falls under. Matching delegates to the project fence's host
// matcher, so a domain row and a scope-rule host column always mean the same
// thing.
func DomainHit(sessionID, host string) (DomainRule, bool) {
	storeMu.RLock()
	set := storeSets[sessionID]
	storeMu.RUnlock()
	if set == nil || !set.EnabledDomains || host == "" {
		return DomainRule{}, false
	}
	for _, rule := range set.Domains {
		if scoperules.HostMatches(rule.Host, host) {
			return rule, true
		}
	}
	return DomainRule{}, false
}

// AllowDomainHit reports whether the host names an entry on the instance's
// default-allow list (fork patch 37): infrastructure the executor may always
// reach. Checked after the deny list — a red line wins — and before the
// project fence, so one instance-level decision covers every project.
func AllowDomainHit(sessionID, host string) (DomainRule, bool) {
	storeMu.RLock()
	set := storeSets[sessionID]
	storeMu.RUnlock()
	if set == nil || !set.EnabledAllowDomains || host == "" {
		return DomainRule{}, false
	}
	for _, rule := range set.AllowDomains {
		if scoperules.HostMatches(rule.Host, host) {
			return rule, true
		}
	}
	return DomainRule{}, false
}

// InheritSessionRules copies the parent session's fence to the child slot
// (fork patch 33), the same mechanism as scoperules.InheritSessionRules: a
// subagent's fresh session id never sees a RunTurnRequest, so without the
// copy its commands and tunnels would fence nothing. The parsed Set is
// read-only after Parse, so sharing the pointer is safe. A child beyond the
// table's capacity is ErrCapacity: silently skipping would open the child
// session unfenced, so the caller must fail the child's creation instead.
func InheritSessionRules(parentID, childID string) error {
	if parentID == "" || childID == "" || parentID == childID {
		return nil
	}
	storeMu.RLock()
	set := storeSets[parentID]
	storeMu.RUnlock()
	if set == nil {
		return nil
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if _, exists := storeSets[childID]; !exists {
		if len(storeRing) >= maxSessions {
			return ErrCapacity
		}
		storeRing = append(storeRing, childID)
	}
	storeSets[childID] = set
	return nil
}

// SetForTest installs one parsed set directly (tests share this package and
// its package-global store). Production code uses SetRules.
func SetForTest(sessionID string, set *Set) {
	storeMu.Lock()
	defer storeMu.Unlock()
	storeSets[sessionID] = set
}

// DropForTest removes one session's set (tests share this package's store).
func DropForTest(sessionID string) {
	storeMu.Lock()
	defer storeMu.Unlock()
	delete(storeSets, sessionID)
	for i, id := range storeRing {
		if id == sessionID {
			storeRing = append(storeRing[:i], storeRing[i+1:]...)
			break
		}
	}
}
