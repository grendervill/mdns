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
	"sync"
	"sync/atomic"
	"time"
)

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
