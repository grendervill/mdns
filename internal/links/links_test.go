package links_test

import (
	"slices"
	"testing"

	"mydns/internal/config"
	"mydns/internal/links"
)

// uris extracts the URIs in order.
func uris(ls []links.Link) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.URI
	}
	return out
}

// TestDefaultPorts checks the device links with default ports: DoH on
// 443 has no port in the URL.
func TestDefaultPorts(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "dns.example.com"

	got := uris(links.Links(cfg))
	want := []string{
		"https://dns.example.com/dns-query",
		"tls://dns.example.com:853",
		"quic://dns.example.com:853",
		"dns.example.com:53",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Links() = %v, want %v", got, want)
	}
}

// TestCustomPorts checks non-default ports everywhere.
func TestCustomPorts(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	cfg.Protocols.DoH.Port = 8443
	cfg.Protocols.DoT.Port = 8853
	cfg.Protocols.DoQ.Port = 8854
	cfg.Protocols.Plain.Port = 5353

	got := uris(links.Links(cfg))
	want := []string{
		"https://dns.example.com:8443/dns-query",
		"tls://dns.example.com:8853",
		"quic://dns.example.com:8854",
		"dns.example.com:5353",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Links() = %v, want %v", got, want)
	}
}

// TestDisabledSkipped checks that disabled protocols produce no links.
func TestDisabledSkipped(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	cfg.Protocols.Plain = config.Protocol{Enabled: false}
	cfg.Protocols.DoQ = config.Protocol{Enabled: false}

	got := uris(links.Links(cfg))
	want := []string{
		"https://dns.example.com/dns-query",
		"tls://dns.example.com:853",
	}
	if !slices.Equal(got, want) {
		t.Errorf("Links() = %v, want %v", got, want)
	}
	for _, l := range links.Links(cfg) {
		if l.Title == "" {
			t.Errorf("link %+v has an empty title", l)
		}
	}
}
