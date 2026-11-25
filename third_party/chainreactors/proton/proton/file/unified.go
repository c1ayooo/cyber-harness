package file

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/utils/ahocorasick"
	"github.com/chainreactors/utils/parsers"
	mmap "github.com/edsrzf/mmap-go"
)

type patternSource struct {
	Pattern     string
	TemplateIdx int
	IsExtractor bool
	OperatorIdx int
	RegexGroup  int
}

type ruleRef struct {
	ID            string
	Severity      string
	Name          string
	Request       *Request
	numMatchers   int
	numExtractors int
}

// ScanGroup holds a set of rules grouped by file extension filter,
// along with precomputed matching state. Treat as an opaque handle
// returned by NewScanner — pass it to FindAll and MatchesFile.
type ScanGroup struct {
	allExtensions bool
	extensions    map[string]struct{}
	useTextOnly   bool
	denyList      map[string]struct{}

	templates      []*ruleRef
	patternSources []patternSource
	prefilter      *linePrefilter
	index          *patternIndex
}

// FindOption configures a FindAll call.
type FindOption func(*findOpts)

type findOpts struct {
	fullMatch      bool
	skipValidation bool
	blockScan      bool
}

func WithFullMatch() FindOption      { return func(o *findOpts) { o.fullMatch = true } }
func WithSkipValidation() FindOption { return func(o *findOpts) { o.skipValidation = true } }
func WithBlockScan() FindOption      { return func(o *findOpts) { o.blockScan = true } }

type patternIndex struct {
	ac               *ahocorasick.Automaton
	literals         []string
	literalToSources map[int][]int
	fallbackSources  []int
}

type matchHit struct {
	Value  string
	Rule   string
	Line   int
	Offset int
}

type fileResult struct {
	matcherHits   [][]matchHit
	extractorHits [][]matchHit
}

type Event = parsers.TemplateEvent

type Finding = parsers.FindingResult

type ScanStats struct {
	Files    int64
	Regions  int64
	Packets  int64
	Bytes    int64
	Findings int64
	Rules    int
}

func (s ScanStats) HumanBytes() string {
	return common.HumanSize(float64(s.Bytes))
}

type Scanner struct {
	Groups  []*ScanGroup
	Options *protocols.ExecuterOptions
	Stats   ScanStats
}

type Rule struct {
	ID       string
	Name     string
	Severity string
	Requests []*Request
}

func extensionKey(req *Request) string {
	if req.allExtensions {
		return "all"
	}
	exts := make([]string, 0, len(req.extensions))
	for ext := range req.extensions {
		exts = append(exts, ext)
	}
	sort.Strings(exts)
	return strings.Join(exts, ",")
}

func NewScanner(inputs []Rule, opts *protocols.ExecuterOptions) *Scanner {
	groupMap := make(map[string]*ScanGroup)

	for inputIdx := range inputs {
		input := &inputs[inputIdx]
		for _, req := range input.Requests {
			key := extensionKey(req)
			group, ok := groupMap[key]
			if !ok {
				group = &ScanGroup{
					allExtensions: req.allExtensions,
					extensions:    make(map[string]struct{}),
					denyList:      make(map[string]struct{}),
				}
				groupMap[key] = group
			}
			for ext := range req.extensions {
				group.extensions[ext] = struct{}{}
			}
			for deny := range req.denyList {
				group.denyList[deny] = struct{}{}
			}
			if req.useTextOnly {
				group.useTextOnly = true
			}
			tmplRef := &ruleRef{ID: input.ID, Severity: input.Severity, Name: input.Name, Request: req}
			if req.CompiledOperators != nil {
				tmplRef.numMatchers = len(req.CompiledOperators.Matchers)
				tmplRef.numExtractors = len(req.CompiledOperators.Extractors)
			}
			tmplIdx := len(group.templates)
			group.templates = append(group.templates, tmplRef)

			if req.CompiledOperators != nil {
				for mIdx, matcher := range req.CompiledOperators.Matchers {
					if matcher.GetType() == operators.RegexMatcher {
						for _, pattern := range matcher.Regex {
							group.patternSources = append(group.patternSources, patternSource{
								Pattern: pattern, TemplateIdx: tmplIdx, OperatorIdx: mIdx,
							})
						}
					}
				}
				for eIdx, extractor := range req.CompiledOperators.Extractors {
					if extractor.GetType() == operators.RegexExtractor {
						for _, pattern := range extractor.Regex {
							group.patternSources = append(group.patternSources, patternSource{
								Pattern: pattern, TemplateIdx: tmplIdx, IsExtractor: true,
								OperatorIdx: eIdx, RegexGroup: extractor.RegexGroup,
							})
						}
					}
				}
			}
		}
	}

	groups := make([]*ScanGroup, 0, len(groupMap))
	for _, group := range groupMap {
		group.prefilter = buildGroupPrefilter(group.templates)
		group.index = buildPatternIndex(group.patternSources)
		groups = append(groups, group)
	}
	return &Scanner{
		Groups:  groups,
		Options: opts,
		Stats:   ScanStats{Rules: len(inputs)},
	}
}

func buildPatternIndex(sources []patternSource) *patternIndex {
	idx := &patternIndex{literalToSources: make(map[int][]int)}
	var allLiterals []string
	litLookup := make(map[string]int)

	for srcIdx, src := range sources {
		lits := extractLiterals(src.Pattern)
		if len(lits) == 0 {
			idx.fallbackSources = append(idx.fallbackSources, srcIdx)
			continue
		}
		for _, lit := range lits {
			lower := strings.ToLower(lit)
			litIdx, ok := litLookup[lower]
			if !ok {
				litIdx = len(allLiterals)
				litLookup[lower] = litIdx
				allLiterals = append(allLiterals, lower)
			}
			idx.literalToSources[litIdx] = append(idx.literalToSources[litIdx], srcIdx)
		}
	}
	idx.literals = allLiterals
	if len(allLiterals) > 0 {
		ac, err := ahocorasick.NewBuilder().
			AddStrings(allLiterals).
			SetMatchKind(ahocorasick.LeftmostFirst).
			Build()
		if err == nil {
			idx.ac = ac
		}
	}
	return idx
}

func buildGroupPrefilter(templates []*ruleRef) *linePrefilter {
	var allLiterals []string
	var hasCaseInsensitive bool

	for _, tmplRef := range templates {
		req := tmplRef.Request
		if req.CompiledOperators == nil {
			continue
		}
		for _, ext := range req.CompiledOperators.Extractors {
			if ext.GetType() != operators.RegexExtractor {
				continue
			}
			for _, pattern := range ext.Regex {
				lits := extractLiterals(pattern)
				if len(lits) == 0 {
					return &linePrefilter{disabled: true}
				}
				allLiterals = append(allLiterals, lits...)
				if strings.HasPrefix(pattern, "(?i)") {
					hasCaseInsensitive = true
				}
			}
		}
		for _, m := range req.CompiledOperators.Matchers {
			switch m.GetType() {
			case operators.RegexMatcher:
				for _, pattern := range m.Regex {
					lits := extractLiterals(pattern)
					if len(lits) == 0 {
						return &linePrefilter{disabled: true}
					}
					allLiterals = append(allLiterals, lits...)
					if strings.HasPrefix(pattern, "(?i)") || m.CaseInsensitive {
						hasCaseInsensitive = true
					}
				}
			case operators.WordsMatcher:
				for _, word := range m.Words {
					if len(word) >= 3 {
						allLiterals = append(allLiterals, word)
					} else {
						return &linePrefilter{disabled: true}
					}
				}
				if m.CaseInsensitive {
					hasCaseInsensitive = true
				}
			case operators.DSLMatcher:
				return &linePrefilter{disabled: true}
			}
		}
	}
	if len(allLiterals) == 0 {
		return &linePrefilter{disabled: true}
	}
	seen := make(map[string]struct{}, len(allLiterals))
	deduped := make([]string, 0, len(allLiterals))
	for _, lit := range allLiterals {
		if _, ok := seen[lit]; !ok {
			seen[lit] = struct{}{}
			deduped = append(deduped, lit)
		}
	}
	allLiterals = deduped

	// When there are many literals, bytes.Contains × N becomes slower than
	// a single AC pass. In that case, disable the prefilter entirely and let
	// patternIndex (which already has its own AC) handle filtering.
	// Benchmark shows the crossover at ~50 patterns; we use a conservative
	// threshold since the prefilter also avoids string(line) conversion.
	const maxPrefilterLiterals = 30

	if len(allLiterals) > maxPrefilterLiterals {
		return &linePrefilter{disabled: true}
	}

	f := &linePrefilter{
		literals:           make([][]byte, len(allLiterals)),
		hasCaseInsensitive: hasCaseInsensitive,
	}
	for i, lit := range allLiterals {
		f.literals[i] = []byte(lit)
	}
	if hasCaseInsensitive {
		f.lowercaseLiterals = make([][]byte, len(allLiterals))
		for i, lit := range allLiterals {
			f.lowercaseLiterals[i] = []byte(strings.ToLower(lit))
		}
	}
	return f
}

// relevantSources returns indices into patternSources that may match the line.
// Uses a reusable bitset to avoid per-line allocation.
func (idx *patternIndex) relevantSources(line string, buf *[]int, seen []bool) []int {
	return idx.relevantSourcesBytes([]byte(strings.ToLower(line)), buf, seen)
}

func (idx *patternIndex) relevantSourcesBytes(lower []byte, buf *[]int, seen []bool) []int {
	if idx == nil || idx.ac == nil {
		return idx.fallbackSources
	}
	result := (*buf)[:0]
	// The prefilter must enumerate ALL literal occurrences, including
	// overlapping ones. A non-overlapping Find loop (leftmost-first) drops a
	// literal whose span shares a start with — or is otherwise shadowed by — a
	// different literal (e.g. "begin rsa private key" is masked by "begin"),
	// which silently excludes that template from the scan whenever another
	// loaded template contributes the shadowing literal. FindAllOverlapping
	// reports every occurrence regardless of the automaton's match kind.
	for _, hit := range idx.ac.FindAllOverlapping(lower) {
		for _, srcIdx := range idx.literalToSources[hit.PatternID] {
			if !seen[srcIdx] {
				seen[srcIdx] = true
				result = append(result, srcIdx)
			}
		}
	}
	if len(result) == 0 && len(idx.fallbackSources) == 0 {
		*buf = result
		return nil
	}
	for _, srcIdx := range idx.fallbackSources {
		if !seen[srcIdx] {
			seen[srcIdx] = true
			result = append(result, srcIdx)
		}
	}
	for _, srcIdx := range result {
		seen[srcIdx] = false
	}
	*buf = result
	return result
}

// ReadFile reads a file (or archive entries) and returns their contents as
// (data, label) pairs for scanning. Handles mmap, text-only filtering, and
// archive extraction internally.
func (s *Scanner) ReadFile(path string, group *ScanGroup) []FileContent {
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 || info.Size() > MaxReadSize() {
		return nil
	}

	atomic.AddInt64(&s.Stats.Files, 1)
	atomic.AddInt64(&s.Stats.Bytes, info.Size())

	ext := strings.ToLower(filepath.Ext(path))
	if IsArchiveExt(ext) {
		return s.readArchive(path, group)
	}

	data := readFileData(path, info.Size())
	if data == nil {
		return nil
	}

	if group.useTextOnly {
		if ext == "" || !IsTextExt(ext) {
			sample := data
			if len(sample) > 1024 {
				sample = sample[:1024]
			}
			if !isTextContent(sample) {
				return nil
			}
		}
	}

	return []FileContent{{Data: data, Label: path}}
}

// FileContent holds raw data read from a file or archive entry.
type FileContent struct {
	Data  []byte
	Label string
}

const mmapMinSize = 32 * 1024

func readFileData(path string, size int64) []byte {
	if size >= mmapMinSize {
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		mapped, err := mmap.Map(f, mmap.RDONLY, 0)
		f.Close()
		if err == nil {
			result := make([]byte, len(mapped))
			copy(result, mapped)
			mapped.Unmap()
			return result
		}
	}
	data, _ := os.ReadFile(path)
	return data
}

func (s *Scanner) readArchive(archivePath string, group *ScanGroup) []FileContent {
	ext := strings.ToLower(filepath.Ext(archivePath))
	switch ext {
	case ".tar":
		return s.readTar(archivePath, nil)
	case ".gz", ".tgz":
		return s.readTarGz(archivePath)
	case ".zip", ".jar", ".apk":
		return s.readZip(archivePath)
	default:
		return nil
	}
}

func (s *Scanner) readTar(archivePath string, r io.Reader) []FileContent {
	if r == nil {
		f, err := os.Open(archivePath)
		if err != nil {
			return nil
		}
		defer f.Close()
		r = f
	}
	tr := tar.NewReader(r)
	var contents []FileContent
	entries := 0
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 || hdr.Size > maxArchiveEntrySize {
			continue
		}
		if ShouldDenyExt(filepath.Ext(hdr.Name)) {
			continue
		}
		entries++
		if entries > maxArchiveEntries {
			break
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxArchiveEntrySize))
		if err != nil || len(data) == 0 {
			continue
		}
		contents = append(contents, FileContent{
			Data:  data,
			Label: fmt.Sprintf("%s:%s", archivePath, hdr.Name),
		})
	}
	return contents
}

func (s *Scanner) readTarGz(archivePath string) []FileContent {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil
	}
	defer gr.Close()
	return s.readTar(archivePath, gr)
}

func (s *Scanner) readZip(archivePath string) []FileContent {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil
	}
	defer r.Close()
	var contents []FileContent
	entries := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 == 0 || int64(f.UncompressedSize64) > maxArchiveEntrySize {
			continue
		}
		if ShouldDenyExt(filepath.Ext(f.Name)) {
			continue
		}
		entries++
		if entries > maxArchiveEntries {
			break
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxArchiveEntrySize))
		rc.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		contents = append(contents, FileContent{
			Data:  data,
			Label: fmt.Sprintf("%s:%s", archivePath, f.Name),
		})
	}
	return contents
}

type TemplateInfo struct {
	ID       string
	Name     string
	Severity string
}

func (g *ScanGroup) Templates() []TemplateInfo {
	out := make([]TemplateInfo, len(g.templates))
	for i, t := range g.templates {
		out[i] = TemplateInfo{ID: t.ID, Name: t.Name, Severity: t.Severity}
	}
	return out
}

func (g *ScanGroup) MatchesFile(path, ext string) bool {
	if IsArchiveExt(ext) {
		return true
	}
	if !g.allExtensions {
		if _, ok := g.extensions[ext]; !ok {
			return false
		}
	}
	if _, ok := g.denyList[ext]; ok {
		return false
	}
	if g.useTextOnly && ext != "" {
		if !IsTextExt(ext) {
			return false
		}
	}
	return true
}

// FindAll runs all patterns against the data and returns findings.
//
//	scanner.FindAll(data, label, group)                       // line-by-line (default)
//	scanner.FindAll(data, label, group, WithFullMatch())      // whole-content matching
//	scanner.FindAll(data, label, group, WithBlockScan())      // sliding-window for binary data
//	scanner.FindAll(data, label, group, WithSkipValidation()) // skip false-positive filter
func (s *Scanner) FindAll(data []byte, label string, group *ScanGroup, opts ...FindOption) []Finding {
	var cfg findOpts
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.blockScan {
		return s.scanMemBlock(data, 0, label, group, cfg.skipValidation)
	}
	if cfg.fullMatch {
		return s.findAllFull(data, label, group, cfg.skipValidation)
	}
	return s.findAllLines(data, label, group, cfg.skipValidation)
}

// findAllLines runs the line-scanning pipeline on raw content and returns findings.
func (s *Scanner) findAllLines(data []byte, filePath string, group *ScanGroup, skipValidation bool) []Finding {
	results := s.initFileResults(group.templates)

	srcBuf := make([]int, 0, len(group.patternSources))
	srcSeen := make([]bool, len(group.patternSources))

	lineNum := 0
	byteOffset := 0
	remaining := data
	for len(remaining) > 0 {
		idx := bytes.IndexByte(remaining, '\n')
		var line []byte
		if idx >= 0 {
			line = remaining[:idx]
			remaining = remaining[idx+1:]
		} else {
			line = remaining
			remaining = nil
		}
		lineNum++
		lineOffset := byteOffset
		byteOffset += len(line) + 1
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		if group.prefilter != nil && !group.prefilter.mayMatch(line) {
			continue
		}

		lineStr := string(line)

		relevant := group.index.relevantSources(lineStr, &srcBuf, srcSeen)
		for _, srcIdx := range relevant {
			src := &group.patternSources[srcIdx]
			re := getOrCompileRE2(src.Pattern)
			if re == nil {
				continue
			}
			if src.IsExtractor {
				matches := re.FindAllStringSubmatch(lineStr, -1)
				if len(matches) == 0 {
					continue
				}
				groupPlusOne := src.RegexGroup + 1
				res := &results[src.TemplateIdx]
				for _, m := range matches {
					if len(m) >= groupPlusOne {
						res.extractorHits[src.OperatorIdx] = append(
							res.extractorHits[src.OperatorIdx],
							matchHit{Value: m[src.RegexGroup], Rule: src.Pattern, Line: lineNum, Offset: lineOffset})
					}
				}
			} else {
				if re.MatchString(lineStr) {
					matched := re.FindAllString(lineStr, -1)
					res := &results[src.TemplateIdx]
					for _, val := range matched {
						res.matcherHits[src.OperatorIdx] = append(
							res.matcherHits[src.OperatorIdx],
							matchHit{Value: val, Rule: src.Pattern, Line: lineNum, Offset: lineOffset})
					}
				}
			}
		}

		for tmplIdx, tmplRef := range group.templates {
			req := tmplRef.Request
			if req.CompiledOperators == nil {
				continue
			}
			for matcherIdx, matcher := range req.CompiledOperators.Matchers {
				switch matcher.GetType() {
				case operators.WordsMatcher:
					if matched, words := req.matchWordsOnCorpus(matcher, lineStr); matched {
						for _, w := range words {
							results[tmplIdx].matcherHits[matcherIdx] = append(
								results[tmplIdx].matcherHits[matcherIdx],
								matchHit{Value: w.Value, Rule: w.Rule, Line: lineNum, Offset: lineOffset})
						}
					}
				case operators.BinaryMatcher:
					if matched, bins := matcher.MatchBinary(lineStr); matched {
						for _, b := range bins {
							results[tmplIdx].matcherHits[matcherIdx] = append(
								results[tmplIdx].matcherHits[matcherIdx],
								matchHit{Value: b.Value, Rule: b.Rule, Line: lineNum, Offset: lineOffset})
						}
					}
				}
			}
		}
	}

	var findings []Finding
	for tmplIdx, tmplRef := range group.templates {
		res := &results[tmplIdx]
		if finding := buildFinding(tmplRef, res, filePath, skipValidation); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

// findAllFull runs all patterns against the full content without line splitting.
func (s *Scanner) findAllFull(data []byte, label string, group *ScanGroup, skipValidation bool) []Finding {
	results := s.initFileResults(group.templates)
	content := string(data)

	srcBuf := make([]int, 0, len(group.patternSources))
	srcSeen := make([]bool, len(group.patternSources))

	relevant := group.index.relevantSources(content, &srcBuf, srcSeen)
	for _, srcIdx := range relevant {
		src := &group.patternSources[srcIdx]
		re := getOrCompileRE2(src.Pattern)
		if re == nil {
			continue
		}
		if src.IsExtractor {
			matches := re.FindAllStringSubmatch(content, -1)
			res := &results[src.TemplateIdx]
			for _, m := range matches {
				val := extractGroupValue(m, src.RegexGroup)
				if val == "" {
					continue
				}
				res.extractorHits[src.OperatorIdx] = append(
					res.extractorHits[src.OperatorIdx],
					matchHit{Value: val, Rule: src.Pattern})
			}
		} else {
			if re.MatchString(content) {
				matched := re.FindAllString(content, -1)
				res := &results[src.TemplateIdx]
				for _, val := range matched {
					res.matcherHits[src.OperatorIdx] = append(
						res.matcherHits[src.OperatorIdx],
						matchHit{Value: val, Rule: src.Pattern})
				}
			}
		}
	}

	for tmplIdx, tmplRef := range group.templates {
		req := tmplRef.Request
		if req.CompiledOperators == nil {
			continue
		}
		for matcherIdx, matcher := range req.CompiledOperators.Matchers {
			switch matcher.GetType() {
			case operators.WordsMatcher:
				if matched, words := req.matchWordsOnCorpus(matcher, content); matched {
					for _, w := range words {
						results[tmplIdx].matcherHits[matcherIdx] = append(
							results[tmplIdx].matcherHits[matcherIdx],
							matchHit{Value: w.Value, Rule: w.Rule})
					}
				}
			case operators.BinaryMatcher:
				if matched, bins := matcher.MatchBinary(content); matched {
					for _, b := range bins {
						results[tmplIdx].matcherHits[matcherIdx] = append(
							results[tmplIdx].matcherHits[matcherIdx],
							matchHit{Value: b.Value, Rule: b.Rule})
					}
				}
			}
		}
	}

	var findings []Finding
	for tmplIdx, tmplRef := range group.templates {
		res := &results[tmplIdx]
		if finding := buildFinding(tmplRef, res, label, skipValidation); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

// extractGroupValue mirrors the raw HaE engine's group extraction with fallback:
// try the requested group, fall back to group 1, then group 0 (full match).
func extractGroupValue(m []string, group int) string {
	if group > 0 && group < len(m) {
		return m[group]
	}
	if len(m) > 1 {
		return m[1]
	}
	if len(m) > 0 {
		return m[0]
	}
	return ""
}

const maxArchiveEntries = 10000
const maxArchiveEntrySize = 100 * 1024 * 1024

func (s *Scanner) initFileResults(templates []*ruleRef) []fileResult {
	results := make([]fileResult, len(templates))
	for i, t := range templates {
		if t.numMatchers > 0 {
			results[i].matcherHits = make([][]matchHit, t.numMatchers)
		}
		if t.numExtractors > 0 {
			results[i].extractorHits = make([][]matchHit, t.numExtractors)
		}
	}
	return results
}


func (request *Request) matchWordsOnCorpus(matcher *operators.Matcher, corpus string) (bool, []operators.MatchHit) {
	if request.staticWordMatchers[matcher] {
		return request.matchWordsStatic(matcher, corpus)
	}
	data := map[string]interface{}{"raw": corpus}
	return matcher.ResultWithMatchedSnippet(matcher.MatchWords(corpus, data))
}

func buildFinding(tmplRef *ruleRef, res *fileResult, filePath string, skipSecretFilter bool) *Finding {
	req := tmplRef.Request
	ops := req.CompiledOperators
	if ops == nil {
		return nil
	}
	matcherCondition := ops.GetMatchersCondition()
	matched := false
	var events []Event

	for idx, matcher := range ops.Matchers {
		hits := res.matcherHits[idx]
		hasMatch := len(hits) > 0
		if matcher.Negative {
			hasMatch = !hasMatch
		}
		if hasMatch {
			name := matcher.Name
			if name == "" {
				name = fmt.Sprintf("matcher-%d", idx)
			}
			for _, h := range hits {
				events = append(events, Event{Type: "match", Name: name, Rule: h.Rule, Value: h.Value, Line: h.Line, Offset: h.Offset})
			}
			matched = true
			if matcherCondition == operators.ORCondition {
				break
			}
		} else if matcherCondition == operators.ANDCondition {
			return nil
		}
	}

	hasExtract := false
	for idx, ext := range ops.Extractors {
		hits := res.extractorHits[idx]
		if len(hits) == 0 {
			continue
		}
		name := ext.Name
		if name == "" {
			name = fmt.Sprintf("extractor-%d", idx)
		}
		for _, h := range hits {
			if !skipSecretFilter && !isLikelySecret(h.Value) {
				continue
			}
			events = append(events, Event{Type: "extract", Name: name, Rule: h.Rule, Value: h.Value, Line: h.Line, Offset: h.Offset})
			if !ext.Internal {
				hasExtract = true
			}
		}
	}

	if !matched && !hasExtract {
		return nil
	}
	if len(ops.Matchers) > 0 && !matched {
		return nil
	}
	cls := "match"
	if hasExtract {
		cls = "extract"
	}
	return &Finding{
		Result: parsers.Result{
			TemplateID:   tmplRef.ID,
			TemplateName: tmplRef.Name,
			Severity:     tmplRef.Severity,
			Matched:      matched,
			Extracted:    hasExtract,
			Events:       events,
		},
		FilePath: filePath,
		Class:    cls,
	}
}
