// Package providers is the built-in catalog of public DNS resolvers:
// identity, section (plain or blocking) and per-transport endpoints.
// The data is read-only; endpoints are verified against the real
// services when the catalog changes.
package providers

import (
	"slices"
	"strings"

	"mydns/internal/config"
)

// Section names: "plain" (no filtering) and "blocking" (filtered or
// family resolvers).
const (
	SectionPlain    = "plain"
	SectionBlocking = "blocking"
)

// Trust levels: how strong the public case for a resolver is. The data
// is static and cited; it is never an invented audit.
const (
	TrustRecommended = "recommended"
	TrustLimited     = "limited"
	TrustUnknown     = "unknown"
)

// Shared trust text: one label and one source link used by several
// providers, kept in one place so the wording cannot drift.
const (
	pgLabel = "рекомендован Privacy Guides"
	pgName  = "Privacy Guides"
	pgURL   = "https://www.privacyguides.org/en/dns/"

	noRecLabel = "нет в рекомендациях"
)

// Trust is the public-source trust rating of a provider: a short level,
// a Russian badge label and note, and the source the rating cites.
type Trust struct {
	Level      string // "recommended" | "limited" | "unknown"
	Label      string // short Russian label for a badge
	Note       string // Russian one-liner (logging/jurisdiction)
	SourceName string // e.g. "Privacy Guides"
	SourceURL  string
}

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
	Trust       Trust

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
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Обезличенные данные запросов, до 25 часов; без PII.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://cloudflare-dns.com/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "1.1.1.1:853", ServerName: "cloudflare-dns.com"}},
		Plain: []Endpoint{{Transport: "plain", Address: "1.1.1.1:53"}, {Transport: "plain", Address: "1.0.0.1:53"}},
	},
	{
		ID:          "google",
		Name:        "Google Public DNS",
		Section:     SectionPlain,
		Description: "Google's public resolver; no filtering.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Временные логи (24–48 ч), юрисдикция США.",
			SourceName: "Google Public DNS Privacy", SourceURL: "https://developers.google.com/speed/public-dns/privacy",
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://dns.google/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "8.8.8.8:853", ServerName: "dns.google"}},
		Plain: []Endpoint{{Transport: "plain", Address: "8.8.8.8:53"}, {Transport: "plain", Address: "8.8.4.4:53"}},
	},
	{
		ID:          "quad9",
		Name:        "Quad9",
		Section:     SectionPlain,
		Description: "Security-focused resolver; blocks known malicious domains.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Данные threat-мониторинга без IP и PII; швейцарский некоммерческий фонд.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://dns.quad9.net/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "9.9.9.9:853", ServerName: "dns.quad9.net"}},
		DoQ:   []Endpoint{{Transport: "doq", Address: "9.9.9.9:853", ServerName: "dns.quad9.net"}},
		Plain: []Endpoint{{Transport: "plain", Address: "9.9.9.9:53"}, {Transport: "plain", Address: "149.112.112.112:53"}},
	},
	{
		ID:          "yandex",
		Name:        "Яндекс DNS",
		Section:     SectionPlain,
		Description: "Public resolver by Yandex.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Юрисдикция РФ; оператор может раскрывать данные по закону.",
			SourceName: "Политика конфиденциальности Яндекса", SourceURL: "https://yandex.ru/legal/confidential/",
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://common.dot.dns.yandex.net/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "common.dot.dns.yandex.net:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "77.88.8.8:53"}, {Transport: "plain", Address: "77.88.8.1:53"}},
	},
	{
		ID:          "adguard-dns",
		Name:        "AdGuard DNS",
		Section:     SectionPlain,
		Description: "AdGuard's public resolver; ad and tracker filtering by default.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Анонимизированная статистика; БД запрошенных доменов за 24 часа.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://dns.adguard-dns.com/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "94.140.14.14:853", ServerName: "dns.adguard-dns.com"}},
		DoQ:   []Endpoint{{Transport: "doq", Address: "94.140.14.14:853", ServerName: "dns.adguard-dns.com"}},
		Plain: []Endpoint{{Transport: "plain", Address: "94.140.14.14:53"}, {Transport: "plain", Address: "94.140.15.15:53"}},
	},
	{
		ID:          "dns-sb",
		Name:        "DNS.SB",
		Section:     SectionPlain,
		Description: "Privacy-friendly Anycast resolver.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Независимый оператор; проверяйте политику.",
			SourceName: "DNS.SB Privacy", SourceURL: "https://dns.sb/privacy/",
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://doh.sb/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "dot.sb:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "185.222.222.222:53"}, {Transport: "plain", Address: "45.11.45.11:53"}},
	},
	{
		ID:          "mullvad",
		Name:        "Mullvad DNS",
		Section:     SectionPlain,
		Description: "Public resolver by Mullvad; no logging.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Политика явно запрещает логирование DNS-запросов.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://dns.mullvad.net/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "dns.mullvad.net:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "194.242.2.2:53"}},
	},
	{
		ID:          "controld",
		Name:        "Control D (Free)",
		Section:     SectionPlain,
		Description: "Control D's free resolver profile.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Бесплатные резолверы не хранят данные; профили с аккаунтом логируют.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://freedns.controld.com/p0"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "p0.freedns.controld.com:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "76.76.2.0:53"}, {Transport: "plain", Address: "76.76.10.0:53"}},
	},
	{
		ID:          "opendns",
		Name:        "OpenDNS",
		Section:     SectionPlain,
		Description: "Cisco's classic resolver; no filtering on the main pair.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Cisco; ведёт логи согласно политике.",
			SourceName: "OpenDNS Privacy", SourceURL: "https://www.opendns.com/privacy-policy/",
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://doh.opendns.com/dns-query"}},
		Plain: []Endpoint{{Transport: "plain", Address: "208.67.222.222:53"}, {Transport: "plain", Address: "208.67.220.220:53"}},
	},

	{
		ID:          "adguard-family",
		Name:        "AdGuard DNS Family",
		Section:     SectionBlocking,
		Description: "Ads, trackers and adult content blocked.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Семейный профиль AdGuard (дополнительно блокирует взрослый контент).",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://family.adguard-dns.com/dns-query"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "94.140.14.15:853", ServerName: "family.adguard-dns.com"}},
		DoQ:   []Endpoint{{Transport: "doq", Address: "94.140.14.15:853", ServerName: "family.adguard-dns.com"}},
		Plain: []Endpoint{{Transport: "plain", Address: "94.140.14.15:53"}, {Transport: "plain", Address: "94.140.15.16:53"}},
	},
	{
		ID:          "cloudflare-family",
		Name:        "Cloudflare Family",
		Section:     SectionBlocking,
		Description: "Malware and adult content blocked.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Тот же резолвер 1.1.1.1 в семейном режиме.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://family.cloudflare-dns.com/dns-query"}},
		Plain: []Endpoint{{Transport: "plain", Address: "1.1.1.3:53"}, {Transport: "plain", Address: "1.0.0.3:53"}},
	},
	{
		ID:          "cleanbrowsing-security",
		Name:        "CleanBrowsing Security",
		Section:     SectionBlocking,
		Description: "Malware, phishing and malicious domains blocked.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Небольшой оператор; смотрите политику.",
			SourceName: "CleanBrowsing Privacy", SourceURL: "https://cleanbrowsing.org/privacy",
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://doh.cleanbrowsing.org/doh/security-filter/"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "security-filter-dns.cleanbrowsing.org:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "185.228.168.9:53"}, {Transport: "plain", Address: "185.228.169.9:53"}},
	},
	{
		ID:          "opendns-familyshield",
		Name:        "OpenDNS FamilyShield",
		Section:     SectionBlocking,
		Description: "Adult content blocked.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Cisco; ведёт логи согласно политике.",
			SourceName: "OpenDNS Privacy", SourceURL: "https://www.opendns.com/privacy-policy/",
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://doh.familyshield.opendns.com/dns-query"}},
		Plain: []Endpoint{{Transport: "plain", Address: "208.67.222.123:53"}, {Transport: "plain", Address: "208.67.220.123:53"}},
	},
	{
		ID:          "yandex-family",
		Name:        "Яндекс DNS Family",
		Section:     SectionBlocking,
		Description: "Adult content blocked.",
		Trust: Trust{
			Level: TrustLimited, Label: noRecLabel,
			Note:       "Юрисдикция РФ; оператор может раскрывать данные по закону.",
			SourceName: "Политика конфиденциальности Яндекса", SourceURL: "https://yandex.ru/legal/confidential/",
		},
		DoT:   []Endpoint{{Transport: "dot", Address: "family.dot.dns.yandex.net:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "77.88.8.7:53"}, {Transport: "plain", Address: "77.88.8.3:53"}},
	},
	{
		ID:          "controld-family",
		Name:        "Control D Family",
		Section:     SectionBlocking,
		Description: "Ads, trackers and adult content blocked.",
		Trust: Trust{
			Level: TrustRecommended, Label: pgLabel,
			Note:       "Семейный бесплатный профиль Control D.",
			SourceName: pgName, SourceURL: pgURL,
		},
		DoH:   []Endpoint{{Transport: "doh", Address: "https://freedns.controld.com/family"}},
		DoT:   []Endpoint{{Transport: "dot", Address: "p1.freedns.controld.com:853"}},
		Plain: []Endpoint{{Transport: "plain", Address: "76.76.2.1:53"}, {Transport: "plain", Address: "76.76.10.1:53"}},
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

// TrustForUpstream resolves the trust rating of a configured upstream
// ID. It matches a provider ID exactly first, then the longest provider
// ID that is a prefix of id followed by "-" (so "cloudflare-doh" resolves
// to "cloudflare"); an unknown ID reports false.
func TrustForUpstream(id string) (Trust, bool) {
	if p, ok := ByID(id); ok {
		return p.Trust, true
	}

	best := ""
	for _, p := range catalog {
		if strings.HasPrefix(id, p.ID+"-") && len(p.ID) > len(best) {
			best = p.ID
		}
	}
	if best == "" {
		return Trust{}, false
	}
	p, _ := ByID(best)
	return p.Trust, true
}
