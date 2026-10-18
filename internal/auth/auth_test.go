package auth_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"mydns/internal/auth"
)

// testPassword is the fixture password used across the hashing tests.
const testPassword = "correct horse battery staple"

// testClock drives session and throttle time in tests.
type testClock struct{ now time.Time }

// advance moves the clock forward.
func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// newTestClock returns a clock frozen at a fixed instant plus a getter
// suitable for the Set*ClockForTests seams.
func newTestClock() (*testClock, func() time.Time) {
	clk := &testClock{now: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	return clk, func() time.Time { return clk.now }
}

// newSessions builds sessions with the given TTL on a controllable clock.
func newSessions(t *testing.T, ttl time.Duration) (*auth.Sessions, *testClock) {
	t.Helper()

	s := auth.NewSessions(ttl)
	clk, now := newTestClock()
	auth.SetSessionsClockForTests(s, now)
	return s, clk
}

// newThrottle builds a throttle on a controllable clock.
func newThrottle(t *testing.T, limit int, window time.Duration) (*auth.Throttle, *testClock) {
	t.Helper()

	th := auth.NewThrottle(limit, window)
	clk, now := newTestClock()
	auth.SetThrottleClockForTests(th, now)
	return th, clk
}

// TestHashVerify checks the PHC string HashPassword emits and that
// Verify accepts the right password and only the right password.
func TestHashVerify(t *testing.T) {
	auth.SetParamsForTests(t, 1024, 1, 1) // 1 MiB: production code path, cheap

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	fields := strings.Split(hash, "$")
	if len(fields) != 6 || fields[0] != "" {
		t.Fatalf("hash = %q, want 6 $-separated fields with an empty algorithm marker", hash)
	}
	if fields[1] != "argon2id" {
		t.Errorf("algorithm = %q, want argon2id", fields[1])
	}
	if fields[2] != "v=19" {
		t.Errorf("version = %q, want v=19", fields[2])
	}
	if fields[3] != "m=1024,t=1,p=1" {
		t.Errorf("params = %q, want m=1024,t=1,p=1", fields[3])
	}
	if strings.Contains(fields[4]+fields[5], "=") {
		t.Errorf("hash = %q, want unpadded (raw std) base64 blobs", hash)
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(fields[4])
	if err != nil {
		t.Fatalf("salt %q is not raw-std base64: %v", fields[4], err)
	}
	if len(salt) != 16 {
		t.Errorf("salt length = %d, want 16", len(salt))
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(fields[5])
	if err != nil {
		t.Fatalf("key %q is not raw-std base64: %v", fields[5], err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	if !auth.Verify(hash, testPassword) {
		t.Errorf("Verify(hash, correct password) = false, want true")
	}
	for _, pw := range []string{"", "wrong", testPassword + " ", "Correct horse battery staple", strings.ToUpper(testPassword)} {
		if auth.Verify(hash, pw) {
			t.Errorf("Verify(hash, %q) = true, want false", pw)
		}
	}

	// A second hash of the same password must use a fresh salt and must
	// still verify.
	again, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() second call error = %v", err)
	}
	if again == hash {
		t.Errorf("two hashes of the same password are identical: %q", again)
	}
	if !auth.Verify(again, testPassword) {
		t.Errorf("Verify(second hash, correct password) = false, want true")
	}
}

// TestHashVerifyProductionParams pins the production cost: silently
// changing it would weaken every stored hash.
func TestHashVerifyProductionParams(t *testing.T) {
	mem, iters, par := auth.ProductionParamsForTests()
	if mem != 64*1024 || iters != 3 || par != 2 {
		t.Errorf("production params = m=%d,t=%d,p=%d, want m=65536,t=3,p=2", mem, iters, par)
	}
}

// TestVerifyUsesHashParams checks that Verify honours the parameters
// embedded in the hash instead of the current package parameters, so a
// stored hash keeps verifying after the cost is raised.
func TestVerifyUsesHashParams(t *testing.T) {
	auth.SetParamsForTests(t, 2048, 2, 1)
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=2048,t=2,p=1$") {
		t.Fatalf("hash = %q, want the m=2048,t=2,p=1 prefix", hash)
	}

	// Change the package cost afterwards: verification must not care.
	auth.SetParamsForTests(t, 1024, 1, 1)
	if !auth.Verify(hash, testPassword) {
		t.Errorf("Verify(hash, correct password) = false after a cost change, want true")
	}
	if auth.Verify(hash, "nope") {
		t.Errorf("Verify(hash, wrong password) = true, want false")
	}
}

// TestVerifyRejectsGarbage checks that every malformed PHC string is
// refused without a panic (and without running argon2 on hostile
// parameters).
func TestVerifyRejectsGarbage(t *testing.T) {
	auth.SetParamsForTests(t, 1024, 1, 1)

	salt := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 16))
	key := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))

	// wellFormed builds a hash that is valid except where a case says
	// otherwise.
	wellFormed := func(alg, ver, cost string) string {
		return "$" + alg + "$v=" + ver + "$" + cost + "$" + salt + "$" + key
	}

	cases := map[string]string{
		"empty":              "",
		"plain text":         "not-a-hash",
		"missing fields":     "$argon2id$v=19$m=1024,t=1,p=1$" + salt,
		"trailing field":     wellFormed("argon2id", "19", "m=1024,t=1,p=1") + "$extra",
		"empty salt":         "$argon2id$v=19$m=1024,t=1,p=1$$" + key,
		"empty key":          "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$",
		"argon2i":            wellFormed("argon2i", "19", "m=1024,t=1,p=1"),
		"argon2d":            wellFormed("argon2d", "19", "m=1024,t=1,p=1"),
		"argon2 without id":  wellFormed("argon2", "19", "m=1024,t=1,p=1"),
		"old version":        wellFormed("argon2id", "18", "m=1024,t=1,p=1"),
		"future version":     wellFormed("argon2id", "20", "m=1024,t=1,p=1"),
		"version junk":       wellFormed("argon2id", "19x", "m=1024,t=1,p=1"),
		"version missing":    wellFormed("argon2id", "", "m=1024,t=1,p=1"),
		"cost missing t,p":   wellFormed("argon2id", "19", "m=1024"),
		"cost reordered":     wellFormed("argon2id", "19", "t=1,m=1024,p=1"),
		"cost extra":         wellFormed("argon2id", "19", "m=1024,t=1,p=1,x=9"),
		"zero memory":        wellFormed("argon2id", "19", "m=0,t=1,p=1"),
		"zero iterations":    wellFormed("argon2id", "19", "m=1024,t=0,p=1"),
		"zero lanes":         wellFormed("argon2id", "19", "m=1024,t=1,p=0"),
		"lanes overflow":     wellFormed("argon2id", "19", "m=1024,t=1,p=256"),
		"memory below 8p":    wellFormed("argon2id", "19", "m=8,t=1,p=2"),
		"memory ceiling":     wellFormed("argon2id", "19", "m=4294967295,t=1,p=1"),
		"iterations ceiling": wellFormed("argon2id", "19", "m=1024,t=4294967295,p=1"),
		"cost not numbers":   wellFormed("argon2id", "19", "m=one,t=1,p=1"),
		"negative memory":    wellFormed("argon2id", "19", "m=-1024,t=1,p=1"),
		"padded salt":        "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "==$" + key,
		"short salt":         "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$" + key,
		"short key":          "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$aGFzaA",
		"long salt":          "$argon2id$v=19$m=1024,t=1,p=1$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 65)) + "$" + key,
		"long key":           "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x04}, 65)),
		"bad salt base64":    "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "!$" + key,
		"bad key base64":     "$argon2id$v=19$m=1024,t=1,p=1$" + salt + "$" + key + "!",
	}

	for name, h := range cases {
		if auth.Verify(h, testPassword) {
			t.Errorf("Verify(%s: %q) = true, want false", name, h)
		}
	}
}

// TestSessions checks session creation, validation, revocation and TTL
// expiry, plus the lazy purge of expired entries.
func TestSessions(t *testing.T) {
	t.Run("create valid revoke", func(t *testing.T) {
		s, _ := newSessions(t, time.Hour)

		token, err := s.Create()
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if len(token) != 43 {
			t.Errorf("token length = %d, want 43 (32 raw URL-safe base64 bytes)", len(token))
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
		if err != nil {
			t.Fatalf("token %q is not raw URL-safe base64: %v", token, err)
		}
		if len(raw) != 32 {
			t.Errorf("token decodes to %d bytes, want 32", len(raw))
		}
		if strings.ContainsAny(token, "=+/") {
			t.Errorf("token %q must be unpadded URL-safe base64", token)
		}

		if !s.Valid(token) {
			t.Errorf("Valid(new token) = false, want true")
		}
		for _, bad := range []string{"", "nonsense", token[:len(token)-1], token + "x", strings.ToUpper(token)} {
			if s.Valid(bad) {
				t.Errorf("Valid(%q) = true, want false", bad)
			}
		}

		second, err := s.Create()
		if err != nil {
			t.Fatalf("Create() second call error = %v", err)
		}
		if second == token {
			t.Errorf("two sessions share the token %q", second)
		}
		if !s.Valid(token) || !s.Valid(second) {
			t.Errorf("Valid() = false for a live session, want true for both")
		}

		s.Revoke(token)
		if s.Valid(token) {
			t.Errorf("Valid(revoked token) = true, want false")
		}
		if !s.Valid(second) {
			t.Errorf("revoking one session invalidated another")
		}
		if n := auth.SessionCountForTests(s); n != 1 {
			t.Errorf("session count = %d after a revoke, want 1", n)
		}

		s.Revoke("never-existed") // must not panic
	})

	t.Run("expiry", func(t *testing.T) {
		s, clk := newSessions(t, time.Hour)

		token, err := s.Create()
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		clk.advance(time.Hour - time.Nanosecond)
		if !s.Valid(token) {
			t.Errorf("Valid() just before the TTL = false, want true")
		}
		clk.advance(time.Nanosecond) // exactly the TTL
		if s.Valid(token) {
			t.Errorf("Valid() at exactly the TTL = true, want false")
		}
		if n := auth.SessionCountForTests(s); n != 0 {
			t.Errorf("expired session not purged by Valid(): count = %d, want 0", n)
		}
	})

	t.Run("purge", func(t *testing.T) {
		s, clk := newSessions(t, time.Hour)

		old, err := s.Create()
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		clk.advance(30 * time.Minute)
		fresh, err := s.Create()
		if err != nil {
			t.Fatalf("Create() second call error = %v", err)
		}
		clk.advance(31 * time.Minute) // old is 61m old, fresh is 31m old

		s.Purge()
		if n := auth.SessionCountForTests(s); n != 1 {
			t.Errorf("Purge() left %d sessions, want 1", n)
		}
		if s.Valid(old) {
			t.Errorf("Valid(expired) = true, want false")
		}
		if !s.Valid(fresh) {
			t.Errorf("Valid(live) = false, want true")
		}
	})

	t.Run("non-positive TTL expires immediately", func(t *testing.T) {
		s, _ := newSessions(t, 0)

		token, err := s.Create()
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if s.Valid(token) {
			t.Errorf("Valid() with TTL 0 = true, want false")
		}
	})

	t.Run("safe under concurrency", func(t *testing.T) {
		s, _ := newSessions(t, time.Hour)

		live, err := s.Create()
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					token, err := s.Create()
					if err != nil {
						t.Errorf("Create() error = %v", err)
						return
					}
					s.Valid(token)
					s.Valid(live)
					s.Revoke(token)
				}
			}()
		}
		wg.Wait()

		if !s.Valid(live) {
			t.Errorf("live session lost under concurrent use")
		}
		if n := auth.SessionCountForTests(s); n != 1 {
			t.Errorf("session count = %d after concurrent create/revoke, want 1", n)
		}
	})
}

// TestThrottle checks the per-IP failure counter: blocking at the
// limit, reset on success, decay after the window, a bounded table and
// safe concurrent use.
func TestThrottle(t *testing.T) {
	const ip = "192.0.2.10"

	t.Run("limit", func(t *testing.T) {
		th, _ := newThrottle(t, 3, time.Minute)

		if !th.Allow(ip) {
			t.Errorf("Allow() before any failure = false, want true")
		}
		th.Fail(ip)
		th.Fail(ip)
		if !th.Allow(ip) {
			t.Errorf("Allow() after 2 failures = false, want true (limit 3)")
		}
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 3 failures = true, want false (limit 3)")
		}
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 4 failures = true, want false")
		}
	})

	t.Run("success resets", func(t *testing.T) {
		th, _ := newThrottle(t, 3, time.Minute)

		th.Fail(ip)
		th.Fail(ip)
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 3 failures = true, want false")
		}

		th.Success(ip)
		if !th.Allow(ip) {
			t.Errorf("Allow() after Success() = false, want true")
		}

		// The counter really restarted: two failures allow, the third
		// blocks again.
		th.Fail(ip)
		th.Fail(ip)
		if !th.Allow(ip) {
			t.Errorf("Allow() after 2 failures post-reset = false, want true")
		}
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 3 failures post-reset = true, want false")
		}
	})

	t.Run("window expiry", func(t *testing.T) {
		th, clk := newThrottle(t, 3, time.Minute)

		th.Fail(ip)
		th.Fail(ip)
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 3 failures = true, want false")
		}

		clk.advance(59 * time.Second)
		if th.Allow(ip) {
			t.Errorf("Allow() 59s into a 1m window = true, want false")
		}

		clk.advance(2 * time.Second) // one second past the window
		if !th.Allow(ip) {
			t.Errorf("Allow() past the window = false, want true")
		}

		// The counter restarted: two failures allow again, the third
		// blocks.
		th.Fail(ip)
		th.Fail(ip)
		if !th.Allow(ip) {
			t.Errorf("Allow() after 2 failures in the new window = false, want true")
		}
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 3 failures in the new window = true, want false")
		}

		// A failure arriving after the window, with no Allow() in
		// between, restarts the counter instead of extending the stale
		// one.
		clk.advance(time.Minute + time.Second)
		th.Fail(ip)
		if !th.Allow(ip) {
			t.Errorf("Allow() after a failure past the window = false, want true (counter restarted)")
		}
		th.Fail(ip)
		th.Fail(ip)
		if th.Allow(ip) {
			t.Errorf("Allow() after 3 failures in the restarted window = true, want false")
		}
	})

	t.Run("per IP", func(t *testing.T) {
		th, _ := newThrottle(t, 2, time.Minute)

		th.Fail("192.0.2.1")
		th.Fail("192.0.2.1")
		if th.Allow("192.0.2.1") {
			t.Errorf("Allow() for the failing IP = true, want false")
		}
		if !th.Allow("192.0.2.2") {
			t.Errorf("Allow() for an unrelated IP = false, want true")
		}
		if !th.Allow("") {
			t.Errorf("Allow() for an untracked key = false, want true")
		}
	})

	t.Run("non-positive limit or window disables throttling", func(t *testing.T) {
		disabled := []*auth.Throttle{
			auth.NewThrottle(0, time.Minute),
			auth.NewThrottle(-1, time.Minute),
			auth.NewThrottle(3, 0),
		}
		for _, th := range disabled {
			for i := 0; i < 100; i++ {
				th.Fail("192.0.2.9")
			}
			th.Success("192.0.2.9")
			if !th.Allow("192.0.2.9") {
				t.Errorf("Allow() with a disabled throttle = false, want true")
			}
			if n := auth.ThrottleSizeForTests(th); n != 0 {
				t.Errorf("disabled throttle tracks %d IPs, want 0", n)
			}
		}
	})

	t.Run("table stays bounded", func(t *testing.T) {
		th, clk := newThrottle(t, 1, time.Minute)

		const total = 5000
		for i := 0; i < total; i++ {
			th.Fail(fmt.Sprintf("198.51.%d.%d", i/256, i%256))
		}

		size := auth.ThrottleSizeForTests(th)
		if size != 4096 {
			t.Fatalf("throttle tracks %d IPs, want exactly 4096 (full table)", size)
		}

		// A fresh IP arriving at a full table is denied rather than
		// tracked, and the table does not grow.
		const fresh = "203.0.113.7"
		if th.Allow(fresh) {
			t.Errorf("Allow(fresh IP) with a full table = true, want false")
		}
		th.Fail(fresh)
		if size := auth.ThrottleSizeForTests(th); size != 4096 {
			t.Errorf("Fail() on a full table grew it to %d, want 4096", size)
		}

		// Once the window passes, expired entries are swept and new IPs
		// are admitted again.
		clk.advance(time.Minute + time.Second)
		if !th.Allow(fresh) {
			t.Errorf("Allow(fresh IP) after the window = false, want true")
		}
		if size := auth.ThrottleSizeForTests(th); size != 0 {
			t.Errorf("expired entries not swept: %d left, want 0", size)
		}
	})

	t.Run("safe under concurrency", func(t *testing.T) {
		th, _ := newThrottle(t, 5, time.Minute)

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				key := fmt.Sprintf("192.0.2.%d", i)
				for j := 0; j < 200; j++ {
					th.Allow(key)
					th.Fail(key)
					if j%10 == 0 {
						th.Success(key)
					}
				}
			}(i)
		}
		wg.Wait()

		if size := auth.ThrottleSizeForTests(th); size > 8 {
			t.Errorf("throttle tracks %d IPs, want at most 8", size)
		}
	})
}
