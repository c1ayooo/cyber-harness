package types

import (
	"github.com/chainreactors/fingers/alias"
	"github.com/chainreactors/fingers/common"
	fingersEngine "github.com/chainreactors/fingers/fingers"
)

// ====================
// Fingerprint
// ====================

type (
	Aliases       = alias.Aliases
	Alias         = alias.Alias
	Framework     = common.Framework
	Frameworks    = common.Frameworks
	Vuln          = common.Vuln
	Vulns         = common.Vulns
	Attributes    = common.Attributes
	ServiceResult = common.ServiceResult
	MatchDetail   = common.MatchDetail
	From          = common.From

	FingerprintType  = common.FingerprintType
	EngineCapability = common.EngineCapability
)

const (
	WebFingerprint     = common.WebFingerprint
	ServiceFingerprint = common.ServiceFingerprint

	FrameFromDefault        = common.FrameFromDefault
	FrameFromACTIVE         = common.FrameFromACTIVE
	FrameFromICO            = common.FrameFromICO
	FrameFromNOTFOUND       = common.FrameFromNOTFOUND
	FrameFromGUESS          = common.FrameFromGUESS
	FrameFromRedirect       = common.FrameFromRedirect
	FrameFromFingers        = common.FrameFromFingers
	FrameFromFingerprintHub = common.FrameFromFingerprintHub
	FrameFromWappalyzer     = common.FrameFromWappalyzer
	FrameFromEhole          = common.FrameFromEhole
	FrameFromGoby           = common.FrameFromGoby
	FrameFromNmap           = common.FrameFromNmap
)

// ====================
// Fingers Library
// ====================

type (
	Finger         = fingersEngine.Finger
	Fingers        = fingersEngine.Fingers
	FingerRule     = fingersEngine.Rule
	FingerRules    = fingersEngine.Rules
	FingerRegexps  = fingersEngine.Regexps
	FingerSender   = fingersEngine.Sender
	FingerCallback = fingersEngine.Callback
)
