package qlog_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"mydns/internal/qlog"
)

// baseTime is a fixed timestamp for query tests; tests bump it per
// entry to keep the insertion order obvious.
var baseTime = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// sampleLog returns a log holding one entry for every outcome, with
// distinct protocols, clients, upstreams and domains.
func sampleLog(t *testing.T) *qlog.Log {
	t.Helper()

	l, err := qlog.New(20, "", 0)
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}

	l.Add(qlog.Entry{Time: baseTime, ClientIP: "192.0.2.1", Proto: "udp", QName: "ads.example.com", Rcode: 0, Blocked: true, BlockSource: "blocklist"})
	l.Add(qlog.Entry{Time: baseTime.Add(1 * time.Second), ClientIP: "192.0.2.2", Proto: "udp", QName: "news.example.org", Rcode: 0, CacheHit: true})
	l.Add(qlog.Entry{Time: baseTime.Add(2 * time.Second), ClientIP: "192.0.2.3", Proto: "doh", QName: "api.example.net", Rcode: 0, Upstream: "google"})
	l.Add(qlog.Entry{Time: baseTime.Add(3 * time.Second), ClientIP: "192.0.2.4", Proto: "dot", QName: "broken.example.io", Rcode: 2})

	return l
}

// qnames projects entries onto their query names; it returns nil for
// an empty slice so comparisons against nil expectations hold.
func qnames(entries []qlog.Entry) []string {
	if len(entries) == 0 {
		return nil
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.QName
	}
	return out
}

// TestQueryFilters checks every filter and the case-insensitive
// substring search, including their combination.
func TestQueryFilters(t *testing.T) {
	tests := []struct {
		name string
		q    qlog.Query
		want []string
	}{
		{"outcome blocked", qlog.Query{Outcome: "blocked"}, []string{"ads.example.com"}},
		{"outcome cached", qlog.Query{Outcome: "cached"}, []string{"news.example.org"}},
		{"outcome upstream", qlog.Query{Outcome: "upstream"}, []string{"api.example.net"}},
		{"outcome error", qlog.Query{Outcome: "error"}, []string{"broken.example.io"}},
		{"proto udp", qlog.Query{Proto: "udp"}, []string{"news.example.org", "ads.example.com"}},
		{"proto doh", qlog.Query{Proto: "doh"}, []string{"api.example.net"}},
		{"client exact", qlog.Query{Client: "192.0.2.3"}, []string{"api.example.net"}},
		{"unknown client", qlog.Query{Client: "198.51.100.9"}, nil},
		{"upstream exact", qlog.Query{Upstream: "google"}, []string{"api.example.net"}},
		{"search qname case-insensitive", qlog.Query{Search: "NEWS.EXAMPLE"}, []string{"news.example.org"}},
		{"search qname substring", qlog.Query{Search: "ADS."}, []string{"ads.example.com"}},
		{"search upstream substring", qlog.Query{Search: "OOGL"}, []string{"api.example.net"}},
		{"search client substring", qlog.Query{Search: "2.4"}, []string{"broken.example.io"}},
		{"search without match", qlog.Query{Search: "nothing"}, nil},
		{"combined proto and outcome", qlog.Query{Proto: "udp", Outcome: "cached"}, []string{"news.example.org"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := sampleLog(t)
			defer l.Close()

			got, total := l.Query(tc.q, 0, 100)
			if total != len(tc.want) {
				t.Fatalf("Query(%+v) total = %d, want %d", tc.q, total, len(tc.want))
			}
			if !reflect.DeepEqual(qnames(got), tc.want) {
				t.Fatalf("Query(%+v) = %v, want %v", tc.q, qnames(got), tc.want)
			}
		})
	}
}

// TestQueryPagination checks paging, the reported total, newest-first
// order and the limit clamp.
func TestQueryPagination(t *testing.T) {
	t.Run("pages", func(t *testing.T) {
		l, err := qlog.New(10, "", 0)
		if err != nil {
			t.Fatalf("New() = %v, want nil", err)
		}
		defer l.Close()

		for i := 1; i <= 5; i++ {
			l.Add(qlog.Entry{
				Time:  baseTime.Add(time.Duration(i) * time.Second),
				QName: fmt.Sprintf("q%d.example.com", i),
			})
		}

		page, total := l.Query(qlog.Query{}, 0, 2)
		if total != 5 {
			t.Fatalf("Query(0,2) total = %d, want 5", total)
		}
		if want := []string{"q5.example.com", "q4.example.com"}; !reflect.DeepEqual(qnames(page), want) {
			t.Fatalf("Query(0,2) = %v, want %v (newest first)", qnames(page), want)
		}

		page, total = l.Query(qlog.Query{}, 2, 2)
		if total != 5 {
			t.Fatalf("Query(2,2) total = %d, want 5", total)
		}
		if want := []string{"q3.example.com", "q2.example.com"}; !reflect.DeepEqual(qnames(page), want) {
			t.Fatalf("Query(2,2) = %v, want %v", qnames(page), want)
		}

		page, total = l.Query(qlog.Query{}, 4, 2)
		if total != 5 {
			t.Fatalf("Query(4,2) total = %d, want 5", total)
		}
		if want := []string{"q1.example.com"}; !reflect.DeepEqual(qnames(page), want) {
			t.Fatalf("Query(4,2) = %v, want %v", qnames(page), want)
		}

		page, total = l.Query(qlog.Query{}, 5, 2)
		if total != 5 {
			t.Fatalf("Query(5,2) total = %d, want 5", total)
		}
		if len(page) != 0 {
			t.Fatalf("Query(5,2) = %v, want an empty page (offset at the end)", qnames(page))
		}

		page, total = l.Query(qlog.Query{}, 99, 2)
		if total != 5 {
			t.Fatalf("Query(99,2) total = %d, want 5", total)
		}
		if len(page) != 0 {
			t.Fatalf("Query(99,2) = %v, want an empty page (offset past the end)", qnames(page))
		}
	})

	t.Run("limit clamp", func(t *testing.T) {
		l, err := qlog.New(600, "", 0)
		if err != nil {
			t.Fatalf("New() = %v, want nil", err)
		}
		defer l.Close()

		for i := 0; i < 600; i++ {
			l.Add(qlog.Entry{Time: baseTime, QName: fmt.Sprintf("q%d.example.com", i)})
		}

		low, total := l.Query(qlog.Query{}, 0, 0)
		if total != 600 {
			t.Fatalf("Query(0,0) total = %d, want 600", total)
		}
		if len(low) != 1 {
			t.Fatalf("Query(0,0) = %d entries, want 1 (limit clamped up)", len(low))
		}

		high, total := l.Query(qlog.Query{}, 0, 10_000)
		if total != 600 {
			t.Fatalf("Query(0,10000) total = %d, want 600", total)
		}
		if len(high) != 500 {
			t.Fatalf("Query(0,10000) = %d entries, want 500 (limit clamped down)", len(high))
		}
	})
}

// TestQueryUnderWraparound writes three times the ring capacity and
// checks that only live entries are counted and that adjacent pages
// never repeat an entry.
func TestQueryUnderWraparound(t *testing.T) {
	const capacity = 4
	const writes = 3 * capacity

	l, err := qlog.New(capacity, "", 0)
	if err != nil {
		t.Fatalf("New() = %v, want nil", err)
	}
	defer l.Close()

	for i := 1; i <= writes; i++ {
		e := qlog.Entry{
			Time:  baseTime.Add(time.Duration(i) * time.Second),
			QName: fmt.Sprintf("q%d.example.com", i),
		}
		if i%2 == 0 {
			e.Upstream = "google"
		}
		l.Add(e)
	}

	first, total := l.Query(qlog.Query{}, 0, 2)
	if total != capacity {
		t.Fatalf("Query(0,2) total = %d, want %d (only live entries)", total, capacity)
	}
	second, total := l.Query(qlog.Query{}, 2, 2)
	if total != capacity {
		t.Fatalf("Query(2,2) total = %d, want %d", total, capacity)
	}
	third, total := l.Query(qlog.Query{}, 4, 2)
	if total != capacity {
		t.Fatalf("Query(4,2) total = %d, want %d", total, capacity)
	}
	if len(third) != 0 {
		t.Fatalf("Query(4,2) = %v, want an empty page", qnames(third))
	}

	got := append(qnames(first), qnames(second)...)
	want := []string{"q12.example.com", "q11.example.com", "q10.example.com", "q9.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pages = %v, want %v", got, want)
	}

	seen := make(map[string]bool, len(got))
	for _, name := range got {
		if seen[name] {
			t.Fatalf("entry %q appears on two pages", name)
		}
		seen[name] = true
	}

	if _, upTotal := l.Query(qlog.Query{Outcome: "upstream"}, 0, 100); upTotal != 2 {
		t.Fatalf("filtered total = %d, want 2 (q10 and q12 are the live upstream hits)", upTotal)
	}
}

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
