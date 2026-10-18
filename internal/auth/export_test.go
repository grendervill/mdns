package auth

import (
	"testing"
	"time"
)

// This file holds the test seams of the package. It is compiled only
// into tests, so the public API stays free of parameters that exist
// solely for determinism.

// SetParamsForTests replaces the argon2id cost used by HashPassword
// with cheaper values and restores the production cost when the test
// ends. Tests use it so a hash does not burn 64 MiB of memory each
// time.
func SetParamsForTests(t *testing.T, mem, iters, par uint32) {
	t.Helper()

	prev := params
	params = argon2Params{mem: mem, iters: iters, par: par}
	t.Cleanup(func() { params = prev })
}

// ProductionParamsForTests reports the cost HashPassword uses unless a
// test overrides it.
func ProductionParamsForTests() (mem, iters, par uint32) {
	return productionParams.mem, productionParams.iters, productionParams.par
}

// SetSessionsClockForTests replaces the clock the sessions read.
func SetSessionsClockForTests(s *Sessions, now func() time.Time) {
	s.now = now
}

// SetThrottleClockForTests replaces the clock the throttle reads.
func SetThrottleClockForTests(th *Throttle, now func() time.Time) {
	th.now = now
}

// SessionCountForTests reports how many tokens the sessions hold,
// including expired ones that have not been purged yet.
func SessionCountForTests(s *Sessions) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tokens)
}

// ThrottleSizeForTests reports how many addresses the throttle tracks.
func ThrottleSizeForTests(th *Throttle) int {
	th.mu.Lock()
	defer th.mu.Unlock()
	return len(th.entries)
}
