// Package dnsname holds the DNS name helpers shared by the config
// validation and the filter engine: normalization, label splitting and
// block-list domain validation.
package dnsname

import (
	"regexp"
	"strings"
)

// domainRe matches a normalized domain with at least two labels; each
// label is 1-63 chars of [a-z0-9-] and does not start or end with a
// dash. Two labels minimum keeps a bare "com" (whole-TLD) rule out.
var domainRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Normalize lowercases a DNS name and drops its trailing dot.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Labels splits a name into its normalized labels; the root is empty.
func Labels(name string) []string {
	name = Normalize(name)
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// Valid reports whether s (already normalized) is a plausible domain
// for a block-list or user rule: at least two labels, labels of
// [a-z0-9-] without leading or trailing dashes, no paths or schemes.
func Valid(s string) bool {
	return len(s) <= 253 && domainRe.MatchString(s)
}
