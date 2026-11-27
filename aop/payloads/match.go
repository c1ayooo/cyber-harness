package payloads

// matches reports whether one type URL is in the payload's URL list (both
// namespaces).
func matches(url string, urls []string) bool {
	for _, candidate := range urls {
		if url == candidate {
			return true
		}
	}
	return false
}
