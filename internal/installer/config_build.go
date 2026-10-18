package installer

import (
	"errors"
	"fmt"
	"strings"

	"mydns/internal/config"
	"mydns/internal/filter"
	"mydns/internal/providers"
)

// endpointPreference is the order in which a provider's endpoints are
// considered when a single upstream has to be picked: the encrypted
// transports first, plain DNS last.
var endpointPreference = []string{"doh", "dot", "doq", "plain"}

// protocolDefaults are the standard ports of the four listener
// protocols, used when a Spec leaves a port at zero.
const (
	defaultPlainPort = 53
	defaultDoHPort   = 443
	defaultDoTPort   = 853
	defaultDoQPort   = 853
)

// tlsModes is the set of certificate sources the non-interactive setup
// accepts.
var tlsModes = map[string]bool{
	"acme":        true,
	"self-signed": true,
	"files":       true,
}

// buildConfig turns a Spec into a validated config: the built-in
// defaults, the TLS mode, one upstream per catalog provider (the
// provider's preferred endpoint), the strategy, the ports and the
// filter preset. Every field of the spec is optional except Domain.
func buildConfig(spec Spec) (*config.Config, error) {
	cfg := config.Default()

	domain := strings.TrimSpace(spec.Domain)
	if domain == "" {
		return nil, errors.New("installer: spec.domain must not be empty")
	}
	if strings.Contains(domain, "/") {
		return nil, fmt.Errorf("installer: spec.domain %q must be a bare domain, without a path", spec.Domain)
	}
	cfg.Domain = domain

	mode := spec.TLSMode
	if mode == "" {
		mode = "self-signed"
	}
	if !tlsModes[mode] {
		return nil, fmt.Errorf("installer: unknown tls mode %q (want acme, self-signed or files)", spec.TLSMode)
	}
	cfg.TLS = config.TLS{Mode: mode}
	switch mode {
	case "acme":
		provider := spec.ACMEProvider
		if provider == "" {
			provider = "letsencrypt"
		}
		cfg.TLS.ACME = config.ACME{
			Provider:           provider,
			Email:              spec.ACMEEmail,
			DirectoryURL:       spec.ACMEDirectory,
			EABKeyID:           spec.EABKid,
			EABHMAC:            spec.EABHMAC,
			InsecureSkipVerify: spec.ACMEInsecure,
		}
	case "files":
		if spec.CertFile == "" || spec.KeyFile == "" {
			return nil, errors.New("installer: tls mode files requires spec.cert_file and spec.key_file")
		}
		cfg.TLS.CertFile = spec.CertFile
		cfg.TLS.KeyFile = spec.KeyFile
	}

	upstreams, err := buildUpstreams(spec.Providers)
	if err != nil {
		return nil, err
	}
	cfg.Upstreams = upstreams

	if spec.Strategy != "" {
		cfg.Strategy = spec.Strategy
	}

	setPort(&cfg.Protocols.Plain, spec.PlainPort, defaultPlainPort)
	setPort(&cfg.Protocols.DoH, spec.DoHPort, defaultDoHPort)
	setPort(&cfg.Protocols.DoT, spec.DoTPort, defaultDoTPort)
	setPort(&cfg.Protocols.DoQ, spec.DoQPort, defaultDoQPort)

	lists, enabled, err := buildFilter(spec.FilterPreset)
	if err != nil {
		return nil, err
	}
	cfg.Filter.Enabled = enabled
	cfg.Filter.Lists = lists

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("installer: built config is invalid: %w", err)
	}
	return cfg, nil
}

// buildUpstreams maps the catalog IDs to one upstream each: the
// provider's preferred endpoint, in the order the IDs are given, which
// also becomes the upstream priority.
func buildUpstreams(ids []string) ([]config.UpstreamConfig, error) {
	if len(ids) == 0 {
		ids = []string{"cloudflare"}
	}
	out := make([]config.UpstreamConfig, 0, len(ids))
	for i, id := range ids {
		p, ok := providers.ByID(id)
		if !ok {
			return nil, fmt.Errorf("installer: unknown provider %q (not in the resolver catalog)", id)
		}
		ep, ok := preferredEndpoint(p)
		if !ok {
			return nil, fmt.Errorf("installer: provider %q has no usable endpoint", id)
		}
		u := ep.UpstreamConfig(p.ID, p.Name)
		u.Priority = i + 1
		out = append(out, u)
	}
	return out, nil
}

// preferredEndpoint picks the first endpoint of the provider in the
// transport preference order.
func preferredEndpoint(p providers.Provider) (providers.Endpoint, bool) {
	eps := p.AllEndpoints()
	for _, want := range endpointPreference {
		for _, ep := range eps {
			if ep.Transport == want {
				return ep, true
			}
		}
	}
	return providers.Endpoint{}, false
}

// setPort enables a protocol on the spec port, or its default when the
// spec leaves it at zero.
func setPort(p *config.Protocol, spec, def int) {
	port := spec
	if port == 0 {
		port = def
	}
	p.Enabled = true
	p.Port = port
}

// buildFilter maps a filter preset to the config fields: "" and "off"
// disable the engine, "basic" and "strict" enable it with the catalog
// lists of the preset.
func buildFilter(preset string) ([]config.FilterList, bool, error) {
	switch preset {
	case "", "off":
		return nil, false, nil
	case "basic", "strict":
		ids, ok := filter.Preset(preset)
		if !ok {
			return nil, false, fmt.Errorf("installer: unknown filter preset %q", preset)
		}
		lists := make([]config.FilterList, 0, len(ids))
		for _, id := range ids {
			lists = append(lists, config.FilterList{ID: id})
		}
		return lists, true, nil
	}
	return nil, false, fmt.Errorf("installer: unknown filter preset %q (want off, basic or strict)", preset)
}
