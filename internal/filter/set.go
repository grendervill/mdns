// Package filter implements the mdns block-list engine: parsing domain
// lists (adblock subsets, hosts files, plain domains), a suffix index
// with rule priorities, user rules, counters and the updater that
// fetches lists over HTTPS.
package filter

import "strings"

// suffixSet stores domains with suffix semantics: a rule for "d"
// covers d itself and every subdomain of d. A lookup walks the query
// name's label suffixes from the most specific to the least and
// returns the first stored one, so the most specific rule wins.
type suffixSet[T any] map[string]T

// add stores v for domain, normalized; empty domains are ignored.
func (s suffixSet[T]) add(domain string, v T) {
	name := normalizeName(domain)
	if name == "" {
		return
	}
	s[name] = v
}

// value looks numLabels up from the most specific suffix to the least
// and returns the first stored value.
func (s suffixSet[T]) value(numLabels []string) (T, bool) {
	for i := 0; i < len(numLabels); i++ {
		if v, ok := s[strings.Join(numLabels[i:], ".")]; ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// normalizeName lowercases a DNS name and drops its trailing dot.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// labels splits a name into its normalized labels; the root is empty.
func labels(name string) []string {
	name = normalizeName(name)
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}
