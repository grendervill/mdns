package filter

import (
	"testing"

	"mydns/internal/dnsname"
)

// TestSuffixSetExactAndSub checks the core semantics: a rule for a
// domain covers the domain itself and every subdomain, but never its
// parents or siblings.
func TestSuffixSetExactAndSub(t *testing.T) {
	set := suffixSet[struct{}]{}
	set.add("b.c.com", struct{}{})

	for _, name := range []string{"b.c.com", "a.b.c.com", "x.y.b.c.com", "b.c.com."} {
		if _, ok := set.value(dnsname.Labels(name)); !ok {
			t.Errorf("value(%q) = miss, want hit", name)
		}
	}
	for _, name := range []string{"c.com", "other.com", "com"} {
		if _, ok := set.value(dnsname.Labels(name)); ok {
			t.Errorf("value(%q) = hit, want miss", name)
		}
	}
}

// TestSuffixSetCaseAndDot checks normalization on both sides of the
// match: mixed case and a trailing dot must not escape a rule.
func TestSuffixSetCaseAndDot(t *testing.T) {
	set := suffixSet[int]{}
	set.add("Example.COM", 7)

	if v, ok := set.value(dnsname.Labels("A.B.example.com.")); !ok || v != 7 {
		t.Errorf("value(A.B.example.com.) = (%v, %v), want (7, true)", v, ok)
	}
}

// TestSuffixSetLongestValue checks that the most specific rule wins.
func TestSuffixSetLongestValue(t *testing.T) {
	set := suffixSet[string]{}
	set.add("c.com", "outer")
	set.add("b.c.com", "inner")

	if v, ok := set.value(dnsname.Labels("a.b.c.com")); !ok || v != "inner" {
		t.Errorf("value(a.b.c.com) = (%q, %v), want (inner, true)", v, ok)
	}
	if v, ok := set.value(dnsname.Labels("x.c.com")); !ok || v != "outer" {
		t.Errorf("value(x.c.com) = (%q, %v), want (outer, true)", v, ok)
	}
}

// TestSuffixSetMiss checks the empty set and unrelated names.
func TestSuffixSetMiss(t *testing.T) {
	set := suffixSet[int]{}
	if _, ok := set.value(dnsname.Labels("example.com")); ok {
		t.Errorf("value on an empty set = hit, want miss")
	}

	set.add("a.com", 1)
	if _, ok := set.value(dnsname.Labels("b.org")); ok {
		t.Errorf("value(b.org) = hit, want miss")
	}
}
