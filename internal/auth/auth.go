// Package auth holds the panel's credentials and abuse controls:
// argon2id password hashing, in-memory session tokens, and a per-IP
// throttle for failed logins. It is transport-agnostic — the HTTP layer
// (internal/panel) decides when a login succeeded and owns the cookies.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	// saltLen and keyLen fix the size of the salt and the derived key
	// in every hash this package writes.
	saltLen = 16
	keyLen  = 32

	// tokenLen is the number of random bytes behind a session token.
	tokenLen = 32

	// maxHashMemKiB and maxHashIters bound what Verify accepts in a
	// PHC string. A corrupt or hand-edited hash must not make the
	// daemon allocate terabytes or spin for hours; argon2 would happily
	// obey such parameters.
	maxHashMemKiB = 2 << 20 // 2 GiB
	maxHashIters  = 1 << 12 // 4096

	// minSaltLen/maxSaltLen and minKeyLen/maxKeyLen bound the decoded
	// salt and key Verify accepts. They sit well outside what
	// HashPassword writes (16 and 32 bytes); their job is to reject
	// truncated nonsense and a hand-edited hash that would ask argon2
	// for an oversized key.
	minSaltLen = 8
	maxSaltLen = 64
	minKeyLen  = 16
	maxKeyLen  = 64
)

// argon2Params is the argon2id cost: memory in KiB, iterations, and
// parallelism (lanes).
type argon2Params struct {
	mem   uint32
	iters uint32
	par   uint32
}

// productionParams is the cost used in production: 64 MiB, 3
// iterations, 2 lanes. It is a separate value so tests can replace
// params without losing the reference.
var productionParams = argon2Params{mem: 64 * 1024, iters: 3, par: 2}

// params is the cost HashPassword uses. Tests shrink it through
// SetParamsForTests (see export_test.go).
var params = productionParams

// HashPassword derives a PHC argon2id string of the form
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
//
// with unpadded (raw std) base64 for the salt and key. The salt is
// random, so hashing the same password twice yields different strings.
// The call is deliberately slow (64 MiB, 3 iterations), so callers
// should expect tens of milliseconds and not run it on a hot path.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}

	p := params
	key := argon2.IDKey([]byte(pw), salt, p.iters, p.mem, uint8(p.par), keyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.mem, p.iters, p.par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether pw matches hash. It accepts only the exact
// PHC format HashPassword writes; anything else — a foreign algorithm
// or version, padded or corrupt base64, out-of-range cost parameters —
// returns false without running argon2. The derived key is compared in
// constant time, and the cost comes from the hash, not from the current
// parameters, so stored hashes survive a cost change.
func Verify(hash, pw string) bool {
	h, err := parseHash(hash)
	if err != nil {
		return false
	}

	key := argon2.IDKey([]byte(pw), h.salt, h.iters, h.mem, uint8(h.par), uint32(len(h.key)))
	return subtle.ConstantTimeCompare(key, h.key) == 1
}

// parsedHash is a decoded PHC argon2id string.
type parsedHash struct {
	mem   uint32
	iters uint32
	par   uint32
	salt  []byte
	key   []byte
}

// parseHash decodes "$argon2id$v=19$m=<KiB>,t=<iters>,p=<lanes>$<salt>$<key>".
// Every deviation is an error: the field count and order are fixed, the
// version must be 19, the parameters must be the ones argon2 accepts
// (and within this package's bounds), and both blobs must be non-empty
// raw-std base64 of a plausible length.
func parseHash(hash string) (*parsedHash, error) {
	fields := strings.Split(hash, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" {
		return nil, errors.New("auth: not an argon2id PHC hash")
	}

	version, err := parseField(fields[2], "v=")
	if err != nil || version != argon2.Version {
		return nil, fmt.Errorf("auth: unsupported argon2 version %q", fields[2])
	}

	cost := strings.Split(fields[3], ",")
	if len(cost) != 3 {
		return nil, fmt.Errorf("auth: bad argon2id parameters %q", fields[3])
	}
	mem, err := parseField(cost[0], "m=")
	if err != nil {
		return nil, err
	}
	iters, err := parseField(cost[1], "t=")
	if err != nil {
		return nil, err
	}
	par, err := parseField(cost[2], "p=")
	if err != nil {
		return nil, err
	}
	if par < 1 || par > 255 || iters < 1 || iters > maxHashIters || mem < 8*par || mem > maxHashMemKiB {
		return nil, fmt.Errorf("auth: argon2id parameters out of range: m=%d,t=%d,p=%d", mem, iters, par)
	}

	salt, err := decodeBlob(fields[4], minSaltLen, maxSaltLen)
	if err != nil {
		return nil, fmt.Errorf("auth: bad argon2id salt: %w", err)
	}
	key, err := decodeBlob(fields[5], minKeyLen, maxKeyLen)
	if err != nil {
		return nil, fmt.Errorf("auth: bad argon2id key: %w", err)
	}

	return &parsedHash{mem: mem, iters: iters, par: par, salt: salt, key: key}, nil
}

// parseField parses a decimal uint32 that must carry exactly the given
// prefix ("m=", "t=", "p=", "v=").
func parseField(s, prefix string) (uint32, error) {
	value, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return 0, fmt.Errorf("auth: field %q lacks the %q prefix", s, prefix)
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("auth: field %q is not a uint32", s)
	}
	return uint32(n), nil
}

// decodeBlob decodes an unpadded base64 value and enforces its length
// bounds. Strict() rejects non-canonical trailing bits and padding.
func decodeBlob(s string, minLen, maxLen int) ([]byte, error) {
	b, err := base64.RawStdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) < minLen || len(b) > maxLen {
		return nil, fmt.Errorf("%d bytes, want %d..%d", len(b), minLen, maxLen)
	}
	return b, nil
}

// Sessions is a set of live login tokens. Tokens are opaque random
// values that map to an expiry; the store lives in memory, so a restart
// logs everybody out. The zero value is not usable — build one with
// NewSessions. Sessions is safe for concurrent use.
type Sessions struct {
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	tokens map[string]time.Time // token -> expiry
}

// NewSessions returns an empty store whose tokens live for ttl. The
// panel passes 30 days. A non-positive ttl makes every token expire
// immediately.
func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{
		ttl:    ttl,
		now:    time.Now,
		tokens: make(map[string]time.Time),
	}
}

// Create mints a new token and records it with a fresh expiry. The
// token is 32 random bytes in unpadded URL-safe base64, ready to be
// dropped into a cookie.
func (s *Sessions) Create() (string, error) {
	buf := make([]byte, tokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = s.now().Add(s.ttl)
	return token, nil
}

// Valid reports whether token is a live session. Expired tokens are
// dropped lazily on every call, which also bounds the map under a
// stream of abandoned sessions.
func (s *Sessions) Valid(token string) bool {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeLocked(now)

	expiry, ok := s.tokens[token]
	return ok && now.Before(expiry)
}

// Revoke drops one token. Revoking an unknown token is a no-op.
func (s *Sessions) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// Purge drops every expired token. Valid calls it; it is exported for
// callers that want to clean up on a timer instead.
func (s *Sessions) Purge() {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)
}

// purgeLocked drops expired tokens. The caller must hold s.mu.
func (s *Sessions) purgeLocked(now time.Time) {
	for token, expiry := range s.tokens {
		if !now.Before(expiry) {
			delete(s.tokens, token)
		}
	}
}

// maxIPs bounds the number of addresses a Throttle tracks. The cap
// exists only to bound memory against a spoofed-source flood; the
// throttle's actual protection is the per-address failure counter, so
// reaching the cap must not deny anyone (see evictOldestLocked).
const maxIPs = 4096

// Throttle counts failed logins per client address and blocks a client
// once the count reaches the limit. A failure is forgotten when it is
// older than the window, so the throttle heals by itself. Throttle is
// safe for concurrent use.
//
// The window slides from the last failure rather than from a fixed
// start: each Fail refreshes the entry's timestamp, so a client that
// keeps failing stays blocked, while a client that stops is released
// one window after its last failure.
//
// At most maxIPs addresses are tracked at once; the table is a bounded
// cache, not a gate — see evictOldestLocked for why the cap never
// refuses an attempt.
type Throttle struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]*throttleEntry
}

// throttleEntry is one address's failure count and the time of its last
// failure.
type throttleEntry struct {
	count int
	last  time.Time
}

// NewThrottle returns a throttle that blocks an address after limit
// failures within window. The panel passes a handful of attempts and a
// few minutes. A non-positive limit or window disables throttling
// entirely (Allow always reports true, Fail is a no-op); callers that
// want a limit must pass positive values.
func NewThrottle(limit int, window time.Duration) *Throttle {
	return &Throttle{
		limit:   limit,
		window:  window,
		now:     time.Now,
		entries: make(map[string]*throttleEntry),
	}
}

// Allow reports whether a login attempt from ip may proceed: true while
// fewer than limit failures are on record for it, false once the limit
// is reached or while ip's entry is still inside the window. Failures
// older than the window are forgotten first. An address with no entry
// — including one the table has evicted, and any address arriving while
// the table is full — is always allowed: only its own failures can
// block it.
func (t *Throttle) Allow(ip string) bool {
	if t.disabled() {
		return true
	}
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := t.entries[ip]
	if entry == nil {
		return true
	}

	if now.Sub(entry.last) >= t.window {
		delete(t.entries, ip)
		return true
	}
	return entry.count < t.limit
}

// Fail records a failed login from ip, extending the address's window.
// At a full table the least recently failing address is evicted to make
// room, so memory stays bounded without ever refusing an attempt.
func (t *Throttle) Fail(ip string) {
	if t.disabled() {
		return
	}
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	entry := t.entries[ip]
	if entry == nil {
		if len(t.entries) >= maxIPs {
			t.evictOldestLocked()
		}
		t.entries[ip] = &throttleEntry{count: 1, last: now}
		return
	}

	if now.Sub(entry.last) >= t.window {
		entry.count = 0
	}
	entry.count++
	entry.last = now
}

// Success clears ip's record after a successful login, so a client that
// mistyped a password a few times starts over.
func (t *Throttle) Success(ip string) {
	if t.disabled() {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip)
}

// disabled reports whether the throttle is switched off. limit and
// window are set once in the constructor and never changed, so reading
// them without the lock is safe.
func (t *Throttle) disabled() bool {
	return t.limit <= 0 || t.window <= 0
}

// evictOldestLocked makes room for one new entry by dropping the entry
// with the oldest last failure. The table is a bounded cache whose only
// purpose is to bound memory; it is deliberately not a gate, so a flood
// from many sources cannot lock a client out of the panel — at worst an
// attacker's own entries rotate through the table, and the legitimate
// admin's next attempt is always allowed (their entry either survives
// or is the one evicted, in which case they start with a clean count).
//
// Since an expired entry is older than every entry still inside the
// window (now-last >= window versus < window), evicting the oldest also
// prefers dropping stale entries, which is why no periodic sweep is
// needed. The caller must hold t.mu.
func (t *Throttle) evictOldestLocked() {
	var (
		oldestIP string
		oldest   time.Time
		found    bool
	)
	for ip, entry := range t.entries {
		if !found || entry.last.Before(oldest) {
			oldestIP, oldest, found = ip, entry.last, true
		}
	}
	if found {
		delete(t.entries, oldestIP)
	}
}
