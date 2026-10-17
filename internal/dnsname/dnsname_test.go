package dnsname_test

import (
	"testing"

	"mydns/internal/dnsname"
)

// TestNormalize checks lowercasing and trailing-dot removal.
func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":    "example.com",
		"ADS.example.com": "ads.example.com",
		"":                "",
		".":               "",
	}
	for in, want := range cases {
		if got := dnsname.Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLabels checks name splitting.
func TestLabels(t *testing.T) {
	got := dnsname.Labels("A.B.example.com.")
	if len(got) != 4 || got[0] != "a" || got[3] != "com" {
		t.Errorf("Labels() = %v, want [a b example com]", got)
	}
	if got := dnsname.Labels(""); len(got) != 0 {
		t.Errorf("Labels(\"\") = %v, want empty", got)
	}
}

// TestValid checks the domain shape rules: at least two labels, no
// leading/trailing dashes, no paths or schemes.
func TestValid(t *testing.T) {
	valid := []string{"example.com", "a.b.example.co.uk", "xn--d1acufc.xn--p1ai", "a-b.example.com"}
	for _, s := range valid {
		if !dnsname.Valid(s) {
			t.Errorf("Valid(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "com", "localhost", "-bad.com", "bad-.com", "x.com/path", "x.com ", "https://x.com", "a..com", "a_b.com"}
	for _, s := range invalid {
		if dnsname.Valid(s) {
			t.Errorf("Valid(%q) = true, want false", s)
		}
	}
}
