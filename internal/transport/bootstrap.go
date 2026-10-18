package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// bootstrapResolver resolves upstream hostnames through plain DNS
// servers addressed by IP. It exists so that a hostname upstream keeps
// working when the system resolver points at this daemon (or at a
// network that cannot resolve the upstream): the lookup never goes
// through the system resolver unless every bootstrap server fails.
//
// Results are cached per hostname for the smallest answer TTL, clamped
// to [30s, 1h]. The resolver is safe for concurrent use.
type bootstrapResolver struct {
	servers []string
	timeout time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry

	dialer net.Dialer
}

// cacheEntry is one cached hostname answer.
type cacheEntry struct {
	addrs   []string
	expires time.Time
}

const (
	// bootstrapTimeout bounds one UDP query to one bootstrap server.
	bootstrapTimeout = 2 * time.Second
	// bootstrapDialTimeout bounds one dial to a resolved address.
	bootstrapDialTimeout = 5 * time.Second
	// bootstrapMinTTL is the shortest time a cached answer is kept,
	// even when the server returned a smaller (or no) TTL.
	bootstrapMinTTL = 30 * time.Second
	// bootstrapMaxTTL is the longest time a cached answer is kept.
	bootstrapMaxTTL = time.Hour
)

// defaultResolver is the resolver every transport uses for hostname
// upstreams: the three well-known public plain-DNS services, reached by
// IP so that bootstrapping cannot loop through the system resolver.
var defaultResolver = newBootstrapResolver([]string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
})

// newBootstrapResolver returns a resolver that queries servers in order.
func newBootstrapResolver(servers []string) *bootstrapResolver {
	return &bootstrapResolver{
		servers: append([]string(nil), servers...),
		timeout: bootstrapTimeout,
		cache:   make(map[string]cacheEntry),
		dialer:  net.Dialer{Timeout: bootstrapDialTimeout},
	}
}

// dialContext dials address over network. IP literals bypass DNS
// entirely; a hostname is resolved through the bootstrap servers and
// the resolved addresses are tried in order. When every bootstrap
// server fails, the lookup falls back to the system resolver.
func (r *bootstrapResolver) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("bootstrap dial %s: %w", address, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		return r.dialer.DialContext(ctx, network, address)
	}

	addrs, err := r.resolveAddr(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("bootstrap dial %s: %w", address, err)
	}

	var errs []error
	for _, addr := range addrs {
		conn, err := r.dialer.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no addresses resolved"))
	}
	return nil, fmt.Errorf("bootstrap dial %s: %w", address, errors.Join(errs...))
}

// resolveAddr returns the addresses to dial for a host:port, resolving
// the hostname when it is not an IP literal. The original address is
// returned unchanged for IP literals.
func (r *bootstrapResolver) resolveAddr(ctx context.Context, address string) ([]string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{address}, nil
	}

	ips, err := r.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip, port))
	}
	return out, nil
}

// resolve returns the cached or freshly resolved addresses for host.
func (r *bootstrapResolver) resolve(ctx context.Context, host string) ([]string, error) {
	host = strings.ToLower(host)

	if addrs, ok := r.cached(host); ok {
		return addrs, nil
	}

	addrs, ttl, bootErr := r.resolveBootstrap(ctx, host)
	if bootErr == nil {
		r.store(host, addrs, ttl)
		return addrs, nil
	}

	sysAddrs, sysErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if sysErr != nil || len(sysAddrs) == 0 {
		if sysErr == nil {
			sysErr = errors.New("no addresses")
		}
		return nil, errors.Join(
			fmt.Errorf("bootstrap lookup %q: %w", host, bootErr),
			fmt.Errorf("system lookup %q: %w", host, sysErr),
		)
	}

	out := make([]string, 0, len(sysAddrs))
	for _, ip := range sysAddrs {
		out = append(out, ip.Unmap().String())
	}
	return out, nil
}

// resolveBootstrap asks the configured servers in order and returns the
// first non-empty answer along with the smallest TTL it contained.
func (r *bootstrapResolver) resolveBootstrap(ctx context.Context, host string) ([]string, time.Duration, error) {
	var errs []error
	for _, server := range r.servers {
		addrs, ttl, err := r.queryServer(ctx, server, host)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", server, err))
			continue
		}
		if len(addrs) > 0 {
			return addrs, ttl, nil
		}
	}
	if len(errs) == 0 {
		// Either no server is configured or every server answered
		// without addresses (NODATA). Fall through to the system
		// resolver: an upstream may live on the local network, where
		// the public bootstrap servers know nothing about it.
		errs = append(errs, errors.New("no addresses returned"))
	}
	return nil, 0, errors.Join(errs...)
}

// queryResult is one A or AAAA answer: its addresses, the smallest TTL
// among them and the exchange error, if any.
type queryResult struct {
	addrs []string
	ttl   time.Duration
	err   error
}

// queryServer sends an A and an AAAA query to one bootstrap server in
// parallel and merges whatever comes back. A missing record type is not
// an error; only a failed exchange for both types is.
func (r *bootstrapResolver) queryServer(ctx context.Context, server, host string) ([]string, time.Duration, error) {
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	results := make(chan queryResult, len(qtypes))
	for _, qtype := range qtypes {
		go func(qtype uint16) {
			results <- r.queryType(ctx, server, host, qtype)
		}(qtype)
	}

	var addrs []string
	var ttl time.Duration
	var errs []error
	for range qtypes {
		res := <-results
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}
		addrs = append(addrs, res.addrs...)
		if len(res.addrs) > 0 && (ttl == 0 || res.ttl < ttl) {
			ttl = res.ttl
		}
	}

	if len(addrs) == 0 {
		if len(errs) == 0 {
			return nil, 0, nil // NODATA: no addresses, no failure
		}
		return nil, 0, errors.Join(errs...)
	}
	if ttl <= 0 {
		ttl = bootstrapMinTTL
	}
	return addrs, ttl, nil
}

// queryType performs one UDP query and extracts the address records of
// the requested type.
func (r *bootstrapResolver) queryType(ctx context.Context, server, host string, qtype uint16) queryResult {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), qtype)

	qctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	client := &dns.Client{Net: "udp", Timeout: r.timeout}
	resp, _, err := client.ExchangeContext(qctx, query, server)
	if err != nil {
		return queryResult{err: fmt.Errorf("query %s %s: %w", dns.TypeToString[qtype], server, err)}
	}
	if resp.Rcode != dns.RcodeSuccess {
		return queryResult{err: fmt.Errorf("query %s %s: rcode %s", dns.TypeToString[qtype], server, dns.RcodeToString[resp.Rcode])}
	}

	var res queryResult
	for _, rr := range resp.Answer {
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ip = rr.A
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ip = rr.AAAA
			}
		}
		if ip == nil {
			continue
		}
		res.addrs = append(res.addrs, ip.String())
		ttl := time.Duration(rr.Header().Ttl) * time.Second
		if res.ttl == 0 || ttl < res.ttl {
			res.ttl = ttl
		}
	}
	return res
}

// cached returns a copy of the cached addresses for host, if still
// valid.
func (r *bootstrapResolver) cached(host string) ([]string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.cache[host]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		delete(r.cache, host)
		return nil, false
	}
	return append([]string(nil), entry.addrs...), true
}

// store caches addrs for host, clamping ttl into the resolver's window.
func (r *bootstrapResolver) store(host string, addrs []string, ttl time.Duration) {
	if len(addrs) == 0 {
		return
	}
	if ttl < bootstrapMinTTL {
		ttl = bootstrapMinTTL
	}
	if ttl > bootstrapMaxTTL {
		ttl = bootstrapMaxTTL
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[host] = cacheEntry{
		addrs:   append([]string(nil), addrs...),
		expires: time.Now().Add(ttl),
	}
}
