package qlog_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mydns/internal/qlog"
)

// entry builds a minimal log entry for name.
func entry(name string) qlog.Entry {
	return qlog.Entry{
		Time:     time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
		ClientIP: "192.0.2.7",
		Proto:    "udp",
		QName:    name,
		QType:    1,
		Rcode:    0,
	}
}

// TestRingBufferLimit checks that the memory buffer keeps the newest
// entries in order.
func TestRingBufferLimit(t *testing.T) {
	l, err := qlog.New(3, "", 0)
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
	defer l.Close()

	for i := 1; i <= 5; i++ {
		l.Add(entry(string(rune('a'-1+i)) + ".example.com"))
	}

	got := l.Recent(10)
	if len(got) != 3 {
		t.Fatalf("Recent(10) length = %d, want 3", len(got))
	}
	want := []string{"c.example.com", "d.example.com", "e.example.com"}
	for i, w := range want {
		if got[i].QName != w {
			t.Fatalf("Recent() #%d = %q, want %q (newest last)", i, got[i].QName, w)
		}
	}
}

// TestRecentSmallerN checks that Recent(n) with n below the buffer
// size returns exactly the newest n entries.
func TestRecentSmallerN(t *testing.T) {
	l, _ := qlog.New(10, "", 0)
	defer l.Close()

	l.Add(entry("one.example.com"))
	l.Add(entry("two.example.com"))

	got := l.Recent(1)
	if len(got) != 1 || got[0].QName != "two.example.com" {
		t.Fatalf("Recent(1) = %v, want just two.example.com", got)
	}
}

// TestJSONLFile checks that entries are appended as one JSON object
// per line.
func TestJSONLFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	l, err := qlog.New(10, path, 1<<20)
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}

	l.Add(entry("example.com"))
	l.Add(entry("example.org"))
	if err := l.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() = %v, want nil", err)
	}
	lines := []qlog.Entry{}
	for _, line := range splitLines(raw) {
		var e qlog.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("line %q is not JSON: %v", line, err)
		}
		lines = append(lines, e)
	}
	if len(lines) != 2 || lines[0].QName != "example.com" || lines[1].QName != "example.org" {
		t.Fatalf("file entries = %+v, want example.com then example.org", lines)
	}
}

// splitLines splits raw into non-empty lines.
func splitLines(raw []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, b := range raw {
		if b == '\n' {
			if i > start {
				out = append(out, raw[start:i])
			}
			start = i + 1
		}
	}
	if start < len(raw) {
		out = append(out, raw[start:])
	}
	return out
}

// TestRotation checks that the file sink rotates to a .1 file once the
// size limit is crossed.
func TestRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	l, err := qlog.New(10, path, 100) // 100 bytes: every entry crosses it
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
	defer l.Close()

	for i := 0; i < 3; i++ {
		l.Add(entry("example.com"))
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("Stat(%s.1) = %v, want the rotated file to exist", path, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Stat(%s) = %v, want the fresh file to exist", path, err)
	}
}

// TestAddSetsZeroTime checks that Add fills the timestamp in when the
// caller left it zero.
func TestAddSetsZeroTime(t *testing.T) {
	l, _ := qlog.New(10, "", 0)
	defer l.Close()

	l.Add(qlog.Entry{QName: "example.com"})
	got := l.Recent(1)
	if len(got) != 1 || got[0].Time.IsZero() {
		t.Fatalf("Recent(1) = %+v, want a filled timestamp", got)
	}
}

// TestCloseIdempotent checks that Close can be called twice.
func TestCloseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	l, _ := qlog.New(10, path, 1<<20)

	if err := l.Close(); err != nil {
		t.Fatalf("Close() #1 = %v, want nil", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close() #2 = %v, want nil", err)
	}
}
