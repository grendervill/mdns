package qlog

import "testing"

// TestOutcome pins the classification precedence: a blocked request
// stays blocked even if it was also served from the cache, a cache hit
// beats an upstream answer, and an entry with neither source is an
// error (typically a SERVFAIL resolved by nobody).
func TestOutcome(t *testing.T) {
	tests := []struct {
		name string
		e    Entry
		want string
	}{
		{"blocked", Entry{Blocked: true}, "blocked"},
		{"cached", Entry{CacheHit: true}, "cached"},
		{"upstream", Entry{Upstream: "google"}, "upstream"},
		{"error without source", Entry{Rcode: 2}, "error"},
		{"zero entry", Entry{}, "error"},
		{"blocked beats cache and upstream", Entry{Blocked: true, CacheHit: true, Upstream: "google"}, "blocked"},
		{"cached beats upstream", Entry{CacheHit: true, Upstream: "google"}, "cached"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := outcome(tc.e); got != tc.want {
				t.Fatalf("outcome(%+v) = %q, want %q", tc.e, got, tc.want)
			}
		})
	}
}
