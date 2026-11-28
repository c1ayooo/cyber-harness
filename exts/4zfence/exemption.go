package fence

import (
	"net/netip"
	"net/url"
	"strings"
)

// ControlPlaneExemption returns the proxy's request-exemption hook (seam G2)
// for one control plane, named by the server URL this node serves it on: the
// fence is a statement about the target range, so
// the executor's calls to its own control plane must always work — forwarded
// unjudged and uncaptured, and capturing them would leak their Authorization
// headers into the traffic view (fork patch 36). When the configured control
// plane itself lives on loopback, the whole loopback family counts as the
// platform — 127.0.0.1, localhost and ::1 are one machine's management plane
// spelled three ways. An empty or unparseable URL exempts nothing.
//
// The policy lives here since E3: the proxy carries a generic exemption hook,
// the composition wires this constructor's result into it.
func ControlPlaneExemption(serverURL string) func(candidate string) bool {
	host := ""
	if parsed, err := url.Parse(strings.TrimSpace(serverURL)); err == nil {
		host = strings.ToLower(parsed.Hostname())
	}
	if host == "" {
		return func(string) bool { return false }
	}
	return func(candidate string) bool {
		if candidate == "" {
			return false
		}
		candidate = strings.ToLower(strings.Trim(strings.TrimSpace(candidate), "[]"))
		if strings.EqualFold(candidate, host) {
			return true
		}
		if loopbackHost(host) && loopbackHost(candidate) {
			return true
		}
		return false
	}
}

// loopbackHost reports whether one host names the node's own loopback: the
// literal localhost, an address in 127.0.0.0/8, or ::1.
func loopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
