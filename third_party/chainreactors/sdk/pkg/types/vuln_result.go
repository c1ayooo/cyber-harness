package types

// TemplateResult is the JSON-serializable form of a neutron template execution.
type TemplateResult struct {
	Target         string                 `json:"target"`
	TemplateID     string                 `json:"template_id"`
	TemplateName   string                 `json:"template_name,omitempty"`
	Severity       string                 `json:"severity,omitempty"`
	Description    string                 `json:"description,omitempty"`
	References     []string               `json:"references,omitempty"`
	Tags           string                 `json:"tags,omitempty"`
	Classification *Classification        `json:"classification,omitempty"`
	Matched        bool                   `json:"matched"`
	Events         []TemplateEvent        `json:"events,omitempty"`
	Request        string                 `json:"request,omitempty"`
	Response       string                 `json:"response,omitempty"`
	PayloadValues  map[string]interface{} `json:"payload_values,omitempty"`
}
