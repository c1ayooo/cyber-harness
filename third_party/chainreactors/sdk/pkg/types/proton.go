package types

import (
	protonFile "github.com/chainreactors/proton/proton/file"
)

// ====================
// Proton
// ====================

type (
	ProtonResult    = protonFile.Finding
	ProtonEvent     = protonFile.Event
	ProtonScanStats = protonFile.ScanStats
	ProtonRule      = protonFile.Rule
)
