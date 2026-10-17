// Package providers is the built-in catalog of public DNS resolvers:
// identity, section (plain or blocking) and per-transport endpoints.
// The data is read-only; endpoints are verified against the real
// services when the catalog changes.
package providers

import (
	"slices"

	"mydns/internal/config"
)

// Section names: "plain" (no filtering) and "blocking" (filtered or
// family resolvers).
const (
	SectionPlain    = "plain"
	SectionBlocking = "blocking"
)

// Endpoint is one way to reach a provider.
type Endpoint struct {
	Transport  string // plain | dot | doh | doq
	Address    string // host:port for plain/dot/doq, an https URL for doh
	ServerName string // SNI for dot/doq addressed by IP
}

// UpstreamConfig turns the endpoint into a server configuration entry.
func (e Endpoint) UpstreamConfig(id, name string) config.UpstreamConfig {
	return config.UpstreamConfig{
		ID:         id,
		Name:       name,
		Transport:  e.Transport,
		Address:    e.Address,
		ServerName: e.ServerName,
		Enabled:    true,
	}
}

// Provider is one public resolver.
type Provider struct {
	ID          string
	Name        string
	Section     string
	Description string

	DoH   []Endpoint
	DoT   []Endpoint
	DoQ   []Endpoint
	Plain []Endpoint
}

// AllEndpoints returns every endpoint of the provider, in a stable
// order: DoH, DoT, DoQ, plain.
func (p Provider) AllEndpoints() []Endpoint {
	out := make([]Endpoint, 0, len(p.DoH)+len(p.DoT)+len(p.DoQ)+len(p.Plain))
	out = append(out, p.DoH...)
	out = append(out, p.DoT...)
	out = append(out, p.DoQ...)
	out = append(out, p.Plain...)
	return out
}

// catalog is the built-in provider list. Verified against the live
// services (dig/kdig/curl from a fresh container); DoQ is offered only
// for providers that answered QUIC probes (Quad9 and AdGuard),
// dns0.eu was removed after the domain stopped resolving.
var catalog = []Provider{
	{
		ID:          "cloudflare",
		Name:        "Cloudflare",
		Section:     SectionPlain,
		Description: "Fastest public resolver; no filtering.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://cloudflare-dns.com/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "1.1.1.1:853", ServerName: "cloudflare-dns.com"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "1.1.1.1:53"}, {Transport: "plain", Address: "1.0.0.1:53"}},
	},
	{
		ID:          "google",
		Name:        "Google Public DNS",
		Section:     SectionPlain,
		Description: "Google's public resolver; no filtering.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://dns.google/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "8.8.8.8:853", ServerName: "dns.google"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "8.8.8.8:53"}, {Transport: "plain", Address: "8.8.4.4:53"}},
	},
	{
		ID:          "quad9",
		Name:        "Quad9",
		Section:     SectionPlain,
		Description: "Security-focused resolver; blocks known malicious domains.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://dns.quad9.net/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "9.9.9.9:853", ServerName: "dns.quad9.net"}},
		DoQ:         []Endpoint{{Transport: "doq", Address: "9.9.9.9:853", ServerName: "dns.quad9.net"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "9.9.9.9:53"}, {Transport: "plain", Address: "149.112.112.112:53"}},
	},
	{
		ID:          "yandex",
		Name:        "Яндекс DNS",
		Section:     SectionPlain,
		Description: "Public resolver by Yandex.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://common.dot.dns.yandex.net/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "common.dot.dns.yandex.net:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "77.88.8.8:53"}, {Transport: "plain", Address: "77.88.8.1:53"}},
	},
	{
		ID:          "adguard-dns",
		Name:        "AdGuard DNS",
		Section:     SectionPlain,
		Description: "AdGuard's public resolver; ad and tracker filtering by default.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://dns.adguard-dns.com/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "94.140.14.14:853", ServerName: "dns.adguard-dns.com"}},
		DoQ:         []Endpoint{{Transport: "doq", Address: "94.140.14.14:853", ServerName: "dns.adguard-dns.com"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "94.140.14.14:53"}, {Transport: "plain", Address: "94.140.15.15:53"}},
	},
	{
		ID:          "dns-sb",
		Name:        "DNS.SB",
		Section:     SectionPlain,
		Description: "Privacy-friendly Anycast resolver.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://doh.sb/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "dot.sb:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "185.222.222.222:53"}, {Transport: "plain", Address: "45.11.45.11:53"}},
	},
	{
		ID:          "mullvad",
		Name:        "Mullvad DNS",
		Section:     SectionPlain,
		Description: "Public resolver by Mullvad; no logging.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://dns.mullvad.net/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "dns.mullvad.net:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "194.242.2.2:53"}},
	},
	{
		ID:          "controld",
		Name:        "Control D (Free)",
		Section:     SectionPlain,
		Description: "Control D's free resolver profile.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://freedns.controld.com/p0"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "p0.freedns.controld.com:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "76.76.2.0:53"}, {Transport: "plain", Address: "76.76.10.0:53"}},
	},
	{
		ID:          "opendns",
		Name:        "OpenDNS",
		Section:     SectionPlain,
		Description: "Cisco's classic resolver; no filtering on the main pair.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://doh.opendns.com/dns-query"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "208.67.222.222:53"}, {Transport: "plain", Address: "208.67.220.220:53"}},
	},

	{
		ID:          "adguard-family",
		Name:        "AdGuard DNS Family",
		Section:     SectionBlocking,
		Description: "Ads, trackers and adult content blocked.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://family.adguard-dns.com/dns-query"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "94.140.14.15:853", ServerName: "family.adguard-dns.com"}},
		DoQ:         []Endpoint{{Transport: "doq", Address: "94.140.14.15:853", ServerName: "family.adguard-dns.com"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "94.140.14.15:53"}, {Transport: "plain", Address: "94.140.15.16:53"}},
	},
	{
		ID:          "cloudflare-family",
		Name:        "Cloudflare Family",
		Section:     SectionBlocking,
		Description: "Malware and adult content blocked.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://family.cloudflare-dns.com/dns-query"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "1.1.1.3:53"}, {Transport: "plain", Address: "1.0.0.3:53"}},
	},
	{
		ID:          "cleanbrowsing-security",
		Name:        "CleanBrowsing Security",
		Section:     SectionBlocking,
		Description: "Malware, phishing and malicious domains blocked.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://doh.cleanbrowsing.org/doh/security-filter/"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "security-filter-dns.cleanbrowsing.org:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "185.228.168.9:53"}, {Transport: "plain", Address: "185.228.169.9:53"}},
	},
	{
		ID:          "opendns-familyshield",
		Name:        "OpenDNS FamilyShield",
		Section:     SectionBlocking,
		Description: "Adult content blocked.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://doh.familyshield.opendns.com/dns-query"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "208.67.222.123:53"}, {Transport: "plain", Address: "208.67.220.123:53"}},
	},
	{
		ID:          "yandex-family",
		Name:        "Яндекс DNS Family",
		Section:     SectionBlocking,
		Description: "Adult content blocked.",
		DoT:         []Endpoint{{Transport: "dot", Address: "family.dot.dns.yandex.net:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "77.88.8.7:53"}, {Transport: "plain", Address: "77.88.8.3:53"}},
	},
	{
		ID:          "controld-family",
		Name:        "Control D Family",
		Section:     SectionBlocking,
		Description: "Ads, trackers and adult content blocked.",
		DoH:         []Endpoint{{Transport: "doh", Address: "https://freedns.controld.com/family"}},
		DoT:         []Endpoint{{Transport: "dot", Address: "p1.freedns.controld.com:853"}},
		Plain:       []Endpoint{{Transport: "plain", Address: "76.76.2.1:53"}, {Transport: "plain", Address: "76.76.10.1:53"}},
	},
}

// List returns the provider catalog (treat the result as read-only).
func List() []Provider {
	return slices.Clone(catalog)
}

// ByID looks a provider up by ID.
func ByID(id string) (Provider, bool) {
	for _, p := range catalog {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}
