package types

import (
	"github.com/chainreactors/neutron/protocols"
	templateHTTP "github.com/chainreactors/neutron/protocols/http"
	templateNetwork "github.com/chainreactors/neutron/protocols/network"
	templateSSL "github.com/chainreactors/neutron/protocols/ssl"
	"github.com/chainreactors/neutron/templates"
)

// ====================
// Template
// ====================

type (
	Template               = templates.Template
	TemplateInfo           = templates.Info
	Classification         = templates.Classification
	TemplateVariable       = protocols.Variable
	TemplateRequest        = protocols.Request
	HTTPTemplateRequest    = templateHTTP.Request
	NetworkTemplateRequest = templateNetwork.Request
	SSLTemplateRequest     = templateSSL.Request
)
