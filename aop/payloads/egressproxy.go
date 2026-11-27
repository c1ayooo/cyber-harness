package payloads

import (
	"encoding/json"
	"strings"

	"google.golang.org/protobuf/types/known/anypb"
)

// EgressProxyPayload binds one session's outbound calls to the project proxy
// the manifest held at dispatch time. Enabled=false (a disabled draft riding
// every turn) is how a session learns the endpoint was switched off.
type EgressProxyPayload struct {
	Enabled  bool   `json:"enabled"`
	Scheme   string `json:"scheme"`
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	URL      string `json:"url,omitempty"`
}

// EgressProxyExtension wraps the project manifest's proxy JSON verbatim — the
// node parses it with the same struct, so the fields stay theirs. An empty
// payload (no proxy configured) returns nil.
func EgressProxyExtension(proxy json.RawMessage) *anypb.Any {
	if len(strings.TrimSpace(string(proxy))) == 0 {
		return nil
	}
	return encodeRaw(EgressProxyExtensionURL, proxy)
}

// ParseEgressProxy decodes the proxy binding. ok is false when the extension
// is absent or malformed.
func ParseEgressProxy(ext *anypb.Any) (payload EgressProxyPayload, ok bool) {
	if ext == nil || !matches(ext.GetTypeUrl(), EgressProxyURLs) {
		return EgressProxyPayload{}, false
	}
	if err := json.Unmarshal(ext.GetValue(), &payload); err != nil {
		return EgressProxyPayload{}, false
	}
	return payload, true
}
