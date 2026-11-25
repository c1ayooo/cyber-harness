package types

import (
	"github.com/chainreactors/utils/httputils"
	"github.com/chainreactors/utils/parsers"
)

// ====================
// Scan Results
// ====================

type (
	GOGOResult    = parsers.GOGOResult
	GOGOResults   = parsers.GOGOResults
	GOGOConfig    = parsers.GOGOConfig
	GOGOData      = parsers.GOGOData
	SprayResult   = parsers.SprayResult
	SpraySource   = parsers.SpraySource
	ZombieResult  = parsers.ZombieResult
	ZombieInput   = parsers.ZombieInput
	ZombieTaskMod = parsers.ZombieTaskMod
	Extracted     = parsers.Extracted
	Extracteds    = parsers.Extracteds
	Extractor     = parsers.Extractor
	Extractors    = parsers.Extractors
	Response      = httputils.Response
	Content       = httputils.Content
	Hashes        = httputils.Hashes

	TemplateEvent = parsers.TemplateEvent
)

var ReadRaw = httputils.ReadRaw

const (
	CheckSource      = parsers.CheckSource
	InitRandomSource = parsers.InitRandomSource
	InitIndexSource  = parsers.InitIndexSource
	RedirectSource   = parsers.RedirectSource
	CrawlSource      = parsers.CrawlSource
	FingerSource     = parsers.FingerSource
	WordSource       = parsers.WordSource
	WafSource        = parsers.WafSource
	RuleSource       = parsers.RuleSource
	BakSource        = parsers.BakSource
	CommonFileSource = parsers.CommonFileSource
	UpgradeSource    = parsers.UpgradeSource
	RetrySource      = parsers.RetrySource
	AppendSource     = parsers.AppendSource
	AppendRuleSource = parsers.AppendRuleSource

)
