package neutron

import "github.com/chainreactors/sdk/pkg/types"

// TemplateResult builds a serializable TemplateResult from the execution result.
func (r *ExecuteResult) TemplateResult(target string) *types.TemplateResult {
	if r == nil {
		return nil
	}
	tr := &types.TemplateResult{
		Target:  target,
		Matched: r.Matched(),
	}
	if tmpl := r.template; tmpl != nil {
		tr.TemplateID = tmpl.Id
		tr.TemplateName = tmpl.Info.Name
		tr.Severity = tmpl.Info.Severity
		tr.Description = tmpl.Info.Description
		tr.References = tmpl.Info.Reference
		tr.Tags = tmpl.Info.Tags
		tr.Classification = tmpl.Info.Classification
	}
	if op := r.Value(); op != nil {
		tr.Events = op.Events
		tr.Request = op.Request
		tr.Response = op.Response
		tr.PayloadValues = op.PayloadValues
	}
	return tr
}
