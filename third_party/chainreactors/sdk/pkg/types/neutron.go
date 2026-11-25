package types

import (
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
)

// ====================
// Neutron Execution
// ====================

type (
	OperatorResult    = operators.Result
	Operators         = operators.Operators
	Matcher           = operators.Matcher
	MatcherType       = operators.MatcherType
	ConditionType     = operators.ConditionType
	OperatorExtractor = operators.Extractor
	ExtractorType     = operators.ExtractorType
	ResultEvent       = protocols.ResultEvent
)

var OpsecError = protocols.OpsecError

const (
	RegexExtractor = operators.RegexExtractor
	KValExtractor  = operators.KValExtractor
	JSONExtractor  = operators.JSONExtractor
	DSLExtractor   = operators.DSLExtractor
	XPathExtractor = operators.XPathExtractor

	WordsMatcher   = operators.WordsMatcher
	RegexMatcher   = operators.RegexMatcher
	BinaryMatcher  = operators.BinaryMatcher
	StatusMatcher  = operators.StatusMatcher
	SizeMatcher    = operators.SizeMatcher
	DSLMatcher     = operators.DSLMatcher
	FaviconMatcher = operators.FaviconMatcher
	JSONMatcher    = operators.JSONMatcher
	XPathMatcher   = operators.XPathMatcher

	ANDCondition = operators.ANDCondition
	ORCondition  = operators.ORCondition
)
