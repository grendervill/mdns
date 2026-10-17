// Package links renders the connection strings devices need for each
// enabled protocol.
package links

import (
	"fmt"

	"mydns/internal/config"
)

// Link is one device-facing connection string.
type Link struct {
	Proto string // doh | dot | doq | plain
	Title string // Russian label for the interfaces
	URI   string
}

// Links returns the links of every enabled protocol, in a stable
// order: DoH, DoT, DoQ, plain.
func Links(cfg *config.Config) []Link {
	var out []Link

	if cfg.Protocols.DoH.Enabled {
		uri := fmt.Sprintf("https://%s/dns-query", cfg.Domain)
		if cfg.Protocols.DoH.Port != 443 {
			uri = fmt.Sprintf("https://%s:%d/dns-query", cfg.Domain, cfg.Protocols.DoH.Port)
		}
		out = append(out, Link{Proto: "doh", Title: "DoH (DNS-over-HTTPS)", URI: uri})
	}
	if cfg.Protocols.DoT.Enabled {
		out = append(out, Link{
			Proto: "dot",
			Title: "DoT (DNS-over-TLS)",
			URI:   fmt.Sprintf("tls://%s:%d", cfg.Domain, cfg.Protocols.DoT.Port),
		})
	}
	if cfg.Protocols.DoQ.Enabled {
		out = append(out, Link{
			Proto: "doq",
			Title: "DoQ (DNS-over-QUIC)",
			URI:   fmt.Sprintf("quic://%s:%d", cfg.Domain, cfg.Protocols.DoQ.Port),
		})
	}
	if cfg.Protocols.Plain.Enabled {
		out = append(out, Link{
			Proto: "plain",
			Title: "Обычный DNS (для роутеров)",
			URI:   fmt.Sprintf("%s:%d", cfg.Domain, cfg.Protocols.Plain.Port),
		})
	}
	return out
}
