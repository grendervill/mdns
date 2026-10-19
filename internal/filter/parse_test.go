package filter_test

import (
	"slices"
	"strings"
	"testing"

	"mydns/internal/filter"
)

// TestParse checks the per-line classifier against every format the
// engine accepts: adblock subsets, hosts files, plain domains, and the
// junk it must count as skipped.
func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		block   []string
		except  []string
		applied int
		skipped int
	}{
		{
			name: "empty lines are no rules",
			in:   "\n  \n\t\n",
		},
		{
			name: "bang comment",
			in:   "! comment\n! another",
		},
		{
			name: "hash comment",
			in:   "# comment\n#",
		},
		{
			name:    "cosmetic rules are skipped",
			in:      "##.banner\n#@#.ads\n#?#.x",
			skipped: 3,
		},
		{
			name:    "domain-scoped cosmetic rules are not host blocks",
			in:      "ya.ru##.banner\nya.ru#@#.ad\nya.ru#?#.x\nya.ru#$#.y\nya.ru##body > div\ngood.example\n",
			block:   []string{"good.example"},
			applied: 1,
			skipped: 5,
		},
		{
			name:    "hosts line with an inline comment",
			in:      "0.0.0.0 ads.x.com # tracker\n127.0.0.1 tracker.example # note",
			block:   []string{"ads.x.com", "tracker.example"},
			applied: 2,
		},
		{
			name: "a bang comment containing a cosmetic marker",
			in:   "! upstream list uses ##.banner\n",
		},
		{
			name:    "hosts zero",
			in:      "0.0.0.0 ads.x.com",
			block:   []string{"ads.x.com"},
			applied: 1,
		},
		{
			name:    "hosts loopback with inline comment",
			in:      "127.0.0.1 a.b.com # tracker",
			block:   []string{"a.b.com"},
			applied: 1,
		},
		{
			name:    "hosts ipv6",
			in:      "::1 v6.example.com",
			block:   []string{"v6.example.com"},
			applied: 1,
		},
		{
			name:    "adblock block",
			in:      "||ads.example.com^",
			block:   []string{"ads.example.com"},
			applied: 1,
		},
		{
			name:    "adblock block normalized",
			in:      "||ADS.Example.COM^",
			block:   []string{"ads.example.com"},
			applied: 1,
		},
		{
			name:    "adblock exception",
			in:      "@@||good.example.com^",
			except:  []string{"good.example.com"},
			applied: 1,
		},
		{
			name:    "adblock modifier skipped",
			in:      "||x.com^$third-party\n||y.com^$important",
			skipped: 2,
		},
		{
			name:    "bare domain",
			in:      "example.com",
			block:   []string{"example.com"},
			applied: 1,
		},
		{
			name:    "bare domain normalized",
			in:      "EXAMPLE.COM.",
			block:   []string{"example.com"},
			applied: 1,
		},
		{
			name:    "bare exception",
			in:      "@@x.com",
			except:  []string{"x.com"},
			applied: 1,
		},
		{
			name:    "not a domain",
			in:      "not a domain",
			skipped: 1,
		},
		{
			name:    "wildcard path skipped",
			in:      "*/ads/*",
			skipped: 1,
		},
		{
			name:    "three token hosts line skipped",
			in:      "0.0.0.0 a.com b.com",
			skipped: 1,
		},
		{
			name:    "anchored path rule skipped",
			in:      "|http://x.com^",
			skipped: 1,
		},
		{
			name:    "single label skipped",
			in:      "localhost",
			skipped: 1,
		},
		{
			name:    "duplicates collapse",
			in:      "a.com\na.com\n||a.com^",
			block:   []string{"a.com"},
			applied: 1,
		},
		{
			name:    "mixed list",
			in:      "! title\n||ads.example.com^\n@@||good.example.com^\n0.0.0.0 tracker.example.org\n##.banner\nplain.example.net\n",
			block:   []string{"ads.example.com", "tracker.example.org", "plain.example.net"},
			except:  []string{"good.example.com"},
			applied: 4,
			skipped: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filter.Parse(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("Parse() = %v, want nil", err)
			}
			if !slices.Equal(got.Block, tt.block) {
				t.Errorf("Block = %v, want %v", got.Block, tt.block)
			}
			if !slices.Equal(got.Except, tt.except) {
				t.Errorf("Except = %v, want %v", got.Except, tt.except)
			}
			if got.Applied != tt.applied {
				t.Errorf("Applied = %d, want %d", got.Applied, tt.applied)
			}
			if got.Skipped != tt.skipped {
				t.Errorf("Skipped = %d, want %d", got.Skipped, tt.skipped)
			}
		})
	}
}

// TestParseOversizeLine checks that one pathological line is skipped
// without affecting the rest of the list.
func TestParseOversizeLine(t *testing.T) {
	big := strings.Repeat("a", 2<<20) + ".com\nok.com\n"

	got, err := filter.Parse(strings.NewReader(big))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if got.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (the oversize line)", got.Skipped)
	}
	if !slices.Equal(got.Block, []string{"ok.com"}) {
		t.Errorf("Block = %v, want [ok.com]", got.Block)
	}
}
