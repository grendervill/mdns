package providers_test

import (
	"net"
	"net/url"
	"testing"

	"mydns/internal/config"
	"mydns/internal/providers"
)

// TestCatalogShape checks the catalog: filled fields, known sections,
// unique IDs and at least one endpoint per provider.
func TestCatalogShape(t *testing.T) {
	list := providers.List()
	if len(list) < 12 {
		t.Fatalf("catalog has %d providers, want at least 12", len(list))
	}

	seen := map[string]bool{}
	sections := map[string]bool{}
	for _, p := range list {
		if p.ID == "" || p.Name == "" || p.Section == "" || p.Description == "" {
			t.Errorf("provider %+v has empty fields", p)
		}
		if p.Section != "plain" && p.Section != "blocking" {
			t.Errorf("provider %q section = %q, want plain or blocking", p.ID, p.Section)
		}
		sections[p.Section] = true
		if seen[p.ID] {
			t.Errorf("provider id %q is duplicated", p.ID)
		}
		seen[p.ID] = true
		if len(p.AllEndpoints()) == 0 {
			t.Errorf("provider %q has no endpoints", p.ID)
		}
	}

	if !sections["plain"] || !sections["blocking"] {
		t.Errorf("sections present = %v, want both plain and blocking", sections)
	}
}

// TestEndpointsShape checks every endpoint's transport, address format
// and SNI rules.
func TestEndpointsShape(t *testing.T) {
	for _, p := range providers.List() {
		for _, e := range p.AllEndpoints() {
			switch e.Transport {
			case "plain", "dot", "doq":
				if _, _, err := net.SplitHostPort(e.Address); err != nil {
					t.Errorf("%s/%s: address %q must be host:port: %v", p.ID, e.Transport, e.Address, err)
				}
			case "doh":
				u, err := url.Parse(e.Address)
				if err != nil || u.Scheme != "https" || u.Host == "" {
					t.Errorf("%s/doh: address %q must be an https URL", p.ID, e.Address)
				}
			default:
				t.Errorf("%s: unknown transport %q", p.ID, e.Transport)
			}
			if (e.Transport == "dot" || e.Transport == "doq") && isIPOnly(e.Address) && e.ServerName == "" {
				t.Errorf("%s/%s: address %q is an IP and needs a server_name", p.ID, e.Transport, e.Address)
			}
		}
	}
}

// isIPOnly reports whether the address's host part is a bare IP.
func isIPOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return net.ParseIP(host) != nil
}

// TestUpstreamConfigMapping checks the conversion to an upstream config
// and that the result validates inside a minimal config.
func TestUpstreamConfigMapping(t *testing.T) {
	p, ok := providers.ByID("cloudflare")
	if !ok {
		t.Fatalf("ByID(cloudflare) = false, want the provider to exist")
	}
	if len(p.AllEndpoints()) == 0 {
		t.Fatal("cloudflare has no endpoints")
	}

	e := p.AllEndpoints()[0]
	uc := e.UpstreamConfig(p.ID+"-"+e.Transport, p.Name)
	if uc.Transport != e.Transport || uc.Address != e.Address || uc.ServerName != e.ServerName || !uc.Enabled {
		t.Errorf("UpstreamConfig() = %+v, want transport/address/server_name from the endpoint, enabled", uc)
	}

	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	cfg.Upstreams = []config.UpstreamConfig{uc}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with the mapped upstream = %v, want nil", err)
	}
}

// TestByIDMissing checks the lookup miss.
func TestByIDMissing(t *testing.T) {
	if _, ok := providers.ByID("nope"); ok {
		t.Errorf("ByID(nope) = true, want false")
	}
}

// TestTrustShape checks every provider carries a complete, honest trust
// rating: filled fields, a known level and an https source link.
func TestTrustShape(t *testing.T) {
	levels := map[string]bool{
		providers.TrustRecommended: true,
		providers.TrustLimited:     true,
		providers.TrustUnknown:     true,
	}

	recommended := 0
	for _, p := range providers.List() {
		tr := p.Trust
		if tr.Level == "" || tr.Label == "" || tr.Note == "" || tr.SourceName == "" || tr.SourceURL == "" {
			t.Errorf("provider %q has an incomplete trust rating: %+v", p.ID, tr)
		}
		if !levels[tr.Level] {
			t.Errorf("provider %q trust level = %q, want recommended, limited or unknown", p.ID, tr.Level)
		}
		u, err := url.Parse(tr.SourceURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Errorf("provider %q trust source %q must be an https URL", p.ID, tr.SourceURL)
		}
		if tr.Level == providers.TrustRecommended {
			recommended++
		}
	}
	if recommended < 5 {
		t.Errorf("catalog has %d recommended providers, want at least 5", recommended)
	}
}

// TestTrustForUpstream checks the ID resolution: an exact provider ID, a
// derived upstream ID (the provider prefix) and an unknown ID.
func TestTrustForUpstream(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want string
	}{
		{"cloudflare", "cloudflare"},
		{"cloudflare-doh", "cloudflare"},
		{"cloudflare-family", "cloudflare-family"},
		{"adguard-family", "adguard-family"},
	} {
		tr, ok := providers.TrustForUpstream(tc.id)
		if !ok {
			t.Errorf("TrustForUpstream(%q) = false, want a rating", tc.id)
			continue
		}
		p, _ := providers.ByID(tc.want)
		if tr != p.Trust {
			t.Errorf("TrustForUpstream(%q) = %+v, want %+v", tc.id, tr, p.Trust)
		}
	}

	if _, ok := providers.TrustForUpstream("unknown-1"); ok {
		t.Errorf(`TrustForUpstream("unknown-1") = true, want false`)
	}
}
