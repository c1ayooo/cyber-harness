package spray

import "github.com/chainreactors/spray/core"

// Option wraps spray/core.Option with SDK-friendly defaults and builders.
type Option struct {
	*core.Option
}

func NewDefaultOption() *Option {
	opt := &Option{Option: &core.Option{}}

	// Request defaults.
	opt.Method = "GET"
	opt.PortRange = "80,443"
	opt.MaxBodyLength = 100
	opt.RandomUserAgent = false
	opt.Headers = []string{
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language: en-US,en;q=0.9",
		"Connection: close",
	}

	// Status defaults.
	opt.BlackStatus = "400,410"
	opt.WhiteStatus = "200"
	opt.FuzzyStatus = "500,501,502,503,301,302,404"
	opt.UniqueStatus = "403,200,404"

	// Check defaults.
	opt.CheckPeriod = 200
	opt.ErrPeriod = 10
	opt.BreakThreshold = 20

	// Recursion defaults.
	opt.Recursive = "current.IsDir()"
	opt.Depth = 0
	opt.Index = "/"
	opt.Random = ""

	// Retry defaults.
	opt.RetryCount = 0
	opt.SimhashDistance = 8

	// Runtime defaults.
	opt.Mod = "path"
	opt.Client = "auto"
	opt.Timeout = 5
	opt.Threads = 20
	opt.PoolSize = 5
	opt.Deadline = 999999

	// SDK output defaults.
	opt.Quiet = true
	opt.NoBar = true
	opt.NoStat = true
	opt.NoColor = false
	opt.Json = false
	opt.FileOutput = "json"

	// Plugin defaults.
	opt.Advance = false
	opt.Finger = false
	opt.CrawlPlugin = false
	opt.BakPlugin = false
	opt.FuzzuliPlugin = false
	opt.CommonPlugin = false
	opt.ActivePlugin = false
	opt.ReconPlugin = false
	opt.CrawlDepth = 3
	opt.AppendDepth = 2

	opt.FingerEngines = "all"

	return opt
}

func cloneOption(opt *Option) *Option {
	if opt == nil || opt.Option == nil {
		return NewDefaultOption()
	}
	coreOpt := *opt.Option
	clone := &Option{Option: &coreOpt}
	clone.URL = cloneStrings(opt.URL)
	clone.CIDRs = cloneStrings(opt.CIDRs)
	clone.Dictionaries = cloneStrings(opt.Dictionaries)
	clone.Rules = cloneStrings(opt.Rules)
	clone.AppendRule = cloneStrings(opt.AppendRule)
	clone.AppendFile = cloneStrings(opt.AppendFile)
	clone.Prefixes = cloneStrings(opt.Prefixes)
	clone.Suffixes = cloneStrings(opt.Suffixes)
	clone.Replaces = cloneStringMap(opt.Replaces)
	clone.Skips = cloneStrings(opt.Skips)
	clone.Headers = cloneStrings(opt.Headers)
	clone.Cookie = cloneStrings(opt.Cookie)
	clone.Extracts = cloneStrings(opt.Extracts)
	clone.Scope = cloneStrings(opt.Scope)
	clone.Verbose = append([]bool(nil), opt.Verbose...)
	clone.Proxies = cloneStrings(opt.Proxies)
	clone.FingerFiles = cloneStrings(opt.FingerFiles)
	return clone
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func (opt *Option) WithThreads(n int) *Option {
	opt.Threads = n
	return opt
}

func (opt *Option) WithTimeout(n int) *Option {
	opt.Timeout = n
	return opt
}

func (opt *Option) WithMethod(method string) *Option {
	opt.Method = method
	return opt
}

func (opt *Option) WithHeaders(headers []string) *Option {
	opt.Headers = headers
	return opt
}

func (opt *Option) WithProxy(proxy string) *Option {
	opt.Proxies = []string{proxy}
	return opt
}

func (opt *Option) WithFinger(enable bool) *Option {
	opt.Finger = enable
	return opt
}

func (opt *Option) WithCrawl(enable bool) *Option {
	opt.CrawlPlugin = enable
	return opt
}

func (opt *Option) WithDepth(depth int) *Option {
	opt.Depth = depth
	return opt
}

func (opt *Option) WithMod(mod string) *Option {
	opt.Mod = mod
	return opt
}
