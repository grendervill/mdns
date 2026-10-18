// Package qlog records resolved queries twice: a bounded in-memory
// ring for the live views, and, when a file is configured, a JSONL
// file with size-based rotation. The file sink is best-effort: a
// failing disk degrades it silently while the in-memory ring keeps
// working, because the journal is an observability aid, not data the
// service depends on.
package qlog

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxQueryLimit caps one page of Query results.
const maxQueryLimit = 500

// Entry is one resolved query. Blocked and BlockSource are filled by
// the filtering engine; other components leave them zero.
type Entry struct {
	Time        time.Time `json:"time"`
	ClientIP    string    `json:"client_ip"`
	Proto       string    `json:"proto"` // udp, tcp, doh, dot, doq
	QName       string    `json:"qname"`
	QType       uint16    `json:"qtype"`
	Rcode       int       `json:"rcode"`
	Upstream    string    `json:"upstream,omitempty"`
	LatencyMS   float64   `json:"latency_ms"`
	CacheHit    bool      `json:"cache_hit"`
	Blocked     bool      `json:"blocked,omitempty"`
	BlockSource string    `json:"block_source,omitempty"`
}

// Query filters the ring and returns one page of matches, newest
// entries first. A zero value matches everything.
type Query struct {
	Search   string // case-insensitive substring of qname, upstream ID or client IP
	Outcome  string // "" | cached | blocked | upstream | error
	Proto    string // "" | udp | tcp | doh | dot | doq
	Client   string // exact client IP or ""
	Upstream string // exact upstream ID or ""
}

// Log is safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	buf    []Entry
	next   int // index of the next write
	filled bool

	file    *os.File
	path    string
	maxSize int64
	size    int64

	// observer is invoked after every Add, outside the log's lock; it
	// feeds the live event stream.
	observer atomic.Pointer[func(Entry)]
}

// New returns a log keeping the newest memoryEntries entries and,
// when file is non-empty, appending them as JSON lines; the file
// rotates to "<file>.1" (replacing any previous one) once it reaches
// maxFileSizeBytes.
func New(memoryEntries int, file string, maxFileSizeBytes int64) (*Log, error) {
	if memoryEntries < 1 {
		memoryEntries = 1
	}

	l := &Log{
		buf:     make([]Entry, memoryEntries),
		path:    file,
		maxSize: maxFileSizeBytes,
	}

	if file != "" {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		if info, err := f.Stat(); err == nil {
			l.size = info.Size()
		}
		l.file = f
	}

	return l, nil
}

// Add appends an entry to the ring and to the file sink. The entry's
// zero timestamp is filled with the current time.
func (l *Log) Add(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}

	l.mu.Lock()
	l.buf[l.next] = e
	l.next++
	if l.next == len(l.buf) {
		l.next = 0
		l.filled = true
	}
	l.writeFile(e)
	l.mu.Unlock()

	// The observer runs outside the lock: it may publish to a bus but
	// must not call back into the log.
	if f := l.observer.Load(); f != nil {
		(*f)(e)
	}
}

// SetObserver installs a callback invoked after every Add; nil removes
// it.
func (l *Log) SetObserver(f func(Entry)) {
	if f == nil {
		l.observer.Store(nil)
		return
	}
	l.observer.Store(&f)
}

// Recent returns up to n newest entries, oldest first.
func (l *Log) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	count := l.next
	if l.filled {
		count = len(l.buf)
	}
	if n > count {
		n = count
	}
	if n <= 0 {
		return nil
	}

	out := make([]Entry, 0, n)
	for i := n; i > 0; i-- {
		idx := (l.next - i + len(l.buf)) % len(l.buf)
		out = append(out, l.buf[idx])
	}
	return out
}

// Query filters the ring (newest entries first) and returns one page
// of matches along with the total number of entries that matched the
// filter. The ring is read under the mutex and matching entries are
// copied out, so the returned page never aliases the live buffer.
//
// The filters are:
//
//   - Search is a case-insensitive substring match against the query
//     name, the upstream ID and the client IP.
//   - Outcome, when set, is one of "cached", "blocked", "upstream" or
//     "error" (see outcome).
//   - Proto, Client and Upstream, when set, must match exactly.
//
// limit is clamped to [1, 500]; a negative offset is treated as zero.
// An offset at or past the total returns an empty page together with
// the untouched total.
func (l *Log) Query(q Query, offset, limit int) (entries []Entry, total int) {
	if limit < 1 {
		limit = 1
	}
	if limit > maxQueryLimit {
		limit = maxQueryLimit
	}
	if offset < 0 {
		offset = 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	count := l.next
	if l.filled {
		count = len(l.buf)
	}

	search := strings.ToLower(q.Search)
	matched := make([]Entry, 0, count)
	for i := 0; i < count; i++ {
		e := l.buf[(l.next-1-i+len(l.buf))%len(l.buf)]
		if !matches(e, q, search) {
			continue
		}
		matched = append(matched, e)
	}

	total = len(matched)
	if offset >= total {
		return nil, total
	}

	end := offset + limit
	if end > total {
		end = total
	}
	return matched[offset:end], total
}

// matches reports whether e satisfies q; search is the already
// lower-cased Search term.
func matches(e Entry, q Query, search string) bool {
	if q.Outcome != "" && outcome(e) != q.Outcome {
		return false
	}
	if q.Proto != "" && e.Proto != q.Proto {
		return false
	}
	if q.Client != "" && e.ClientIP != q.Client {
		return false
	}
	if q.Upstream != "" && e.Upstream != q.Upstream {
		return false
	}
	if search != "" {
		return strings.Contains(strings.ToLower(e.QName), search) ||
			strings.Contains(strings.ToLower(e.Upstream), search) ||
			strings.Contains(strings.ToLower(e.ClientIP), search)
	}
	return true
}

// outcome classifies one entry by how its answer was produced. The
// order matters: a blocked request stays blocked even when a cached
// answer was served, a cache hit outranks an upstream lookup, and an
// entry with neither a cache nor an upstream source failed (for
// example, every upstream was down and the answer was SERVFAIL).
//
// This mirrors the classification the stats package will need; R7
// deliberately accepts that duplication.
func outcome(e Entry) string {
	switch {
	case e.Blocked:
		return "blocked"
	case e.CacheHit:
		return "cached"
	case e.Upstream != "":
		return "upstream"
	default:
		return "error"
	}
}

// Close closes the file sink; it is safe to call more than once.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// writeFile appends one JSON line, rotating first when the current
// file already crossed the size limit. The caller must hold l.mu.
func (l *Log) writeFile(e Entry) {
	if l.file == nil {
		return
	}

	if l.maxSize > 0 && l.size >= l.maxSize {
		l.rotate()
		if l.file == nil {
			return
		}
	}

	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')

	n, err := l.file.Write(line)
	if err != nil {
		// The file sink is best-effort: give up on it rather than
		// writing half-lines forever.
		_ = l.file.Close()
		l.file = nil
		return
	}
	l.size += int64(n)
}

// rotate replaces "<path>.1" with the current file and starts a fresh
// one. A failed rotation disables the file sink. The caller must hold
// l.mu.
func (l *Log) rotate() {
	_ = l.file.Close()

	if err := os.Rename(l.path, l.path+".1"); err != nil {
		l.file = nil
		return
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		l.file = nil
		return
	}
	l.file = f
	l.size = 0
}
