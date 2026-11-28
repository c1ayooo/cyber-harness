package provider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Each request captures its own conversation: a shared provider may serve
// concurrent sessions, so the session header must never be mutable provider state.
func (p *OpenAIProvider) requestHeaders(ctx context.Context, completion *ChatCompletionRequest) func(*http.Request) {
	sessionID := ""
	if completion != nil {
		sessionID = completion.ConversationID
		if sessionID == "" {
			sessionID = completion.SessionID
		}
	}
	if sessionID == "" {
		sessionID, _ = ctx.Value(conversationKey{}).(string)
	}
	return func(req *http.Request) {
		if p.config.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
		}
		u, err := url.Parse(p.config.BaseURL)
		if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "opencode.ai") {
			return
		}
		req.Header.Set("User-Agent", "cyber-harness/0.x")
		id := sessionID
		if id == "" {
			// Catalog, activation and other one-shot calls have no agent
			// conversation; use a separate identity for this provider instance.
			id = p.auxiliarySessionID
		}
		req.Header.Set("x-opencode-session", id)
	}
}
