package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
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
// to [30s, 1h]. A failure is cached too, briefly, so that repeated dials
// while the resolver is broken fail fast instead of re-querying for
// every connection. The resolver is safe for concurrent use.
type bootstrapResolver struct {
	servers []string
	timeout time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry

	dialer net.Dialer

	// lookupSystem is the system resolver the fallback uses; nil means
	// net.DefaultResolver. Tests inject one to observe the fallback.
	lookupSystem func(ctx context.Context, host string) ([]netip.Addr, error)
	// systemNameservers reads the system nameservers; nil means
	// readResolvConfNameservers. It feeds the loop-safety check.
	systemNameservers func() []string

	sysOnce     sync.Once
	sysLoopback bool
}

// cacheEntry is one cached hostname answer, or a remembered failure
// when err is non-nil and addrs is empty.
type cacheEntry struct {
	addrs   []string
	expires time.Time
	err     error
}

const (
	// bootstrapTimeout bounds one UDP query to one bootstrap server.
	bootstrapTimeout = 2 * time.Second
	// bootstrapDialTimeout bounds one dial to a resolved address.
	bootstrapDialTimeout = 5 * time.Second
	// bootstrapFallbackTimeout bounds the whole system-resolver
	// fallback, derived from the caller's context. The fallback is a
	// last resort: it must not hold a dial for longer than a query can
	// tolerate.
	bootstrapFallbackTimeout = 2 * time.Second
	// bootstrapMinTTL is the shortest time a cached answer is kept,
	// even when the server returned a smaller (or no) TTL.
	bootstrapMinTTL = 30 * time.Second
	// bootstrapMaxTTL is the longest time a cached answer is kept.
	bootstrapMaxTTL = time.Hour
	// bootstrapNegativeTTL is how long a failed resolution is
	// remembered, so dials while the resolver is broken fail fast.
	bootstrapNegativeTTL = 30 * time.Second
	// resolvConfPath is where the system nameservers are read from for
	// the loop-safety check.
	resolvConfPath = "/etc/resolv.conf"
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
		lookupSystem: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
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

// resolve returns the cached or freshly resolved addresses for host. A
// remembered failure (a negative cache entry) is returned as an error,
// so a dial while the resolver is broken fails without a new query.
func (r *bootstrapResolver) resolve(ctx context.Context, host string) ([]string, error) {
	host = strings.ToLower(host)

	if addrs, err, ok := r.cached(host); ok {
		return addrs, err
	}

	addrs, ttl, bootErr := r.resolveBootstrap(ctx, host)
	if bootErr == nil {
		sortV4First(addrs)
		r.store(host, addrs, ttl)
		return addrs, nil
	}
	bootErr = fmt.Errorf("bootstrap lookup %q: %w", host, bootErr)

	// A system resolver whose nameservers are all loopback points back
	// at this daemon: the fallback would re-enter here and loop. Skip
	// it and let the bootstrap error propagate.
	if r.systemResolverLoopback() {
		r.storeFailure(host, bootErr)
		return nil, bootErr
	}

	fctx, cancel := context.WithTimeout(ctx, bootstrapFallbackTimeout)
	defer cancel()
	sysAddrs, sysErr := r.lookupSystem(fctx, host)
	if sysErr != nil || len(sysAddrs) == 0 {
		if sysErr == nil {
			sysErr = errors.New("no addresses")
		}
		err := errors.Join(bootErr, fmt.Errorf("system lookup %q: %w", host, sysErr))
		r.storeFailure(host, err)
		return nil, err
	}

	out := make([]string, 0, len(sysAddrs))
	for _, ip := range sysAddrs {
		out = append(out, ip.Unmap().String())
	}
	sortV4First(out)
	return out, nil
}

// sortV4First moves IPv4 addresses ahead of IPv6 ones, preserving the
// order within each family. The dial loop is sequential, so this
// approximates Happy Eyeballs: with a blackholed v6 route, trying the
// IPv4 address first keeps the exchange inside the client's deadline.
func sortV4First(addrs []string) {
	sort.SliceStable(addrs, func(i, j int) bool {
		a, aerr := netip.ParseAddr(addrs[i])
		b, berr := netip.ParseAddr(addrs[j])
		if aerr != nil || berr != nil {
			return false
		}
		return a.Is4() && !b.Is4()
	})
}

// systemResolverLoopback reports whether every system nameserver is a
// loopback address. The answer is computed once per resolver.
func (r *bootstrapResolver) systemResolverLoopback() bool {
	r.sysOnce.Do(func() {
		fn := r.systemNameservers
		if fn == nil {
			fn = readResolvConfNameservers
		}
		r.sysLoopback = allLoopback(fn())
	})
	return r.sysLoopback
}

// allLoopback reports whether servers is non-empty and every entry is a
// loopback address (127.0.0.0/8 or ::1). An empty list is not treated
// as loopback: with nothing to read, the fallback is left in place.
func allLoopback(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	for _, s := range servers {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !addr.IsLoopback() {
			return false
		}
	}
	return true
}

// readResolvConfNameservers parses the nameserver lines of resolv.conf.
// A missing or unreadable file yields no nameservers.
func readResolvConfNameservers() []string {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return nil
	}

	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
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

// cached returns a copy of the cached addresses for host, a remembered
// failure, or ok=false when nothing valid is cached.
func (r *bootstrapResolver) cached(host string) ([]string, error, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.cache[host]
	if !ok {
		return nil, nil, false
	}
	if time.Now().After(entry.expires) {
		delete(r.cache, host)
		return nil, nil, false
	}
	if entry.err != nil {
		return nil, entry.err, true
	}
	return append([]string(nil), entry.addrs...), nil, true
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

// storeFailure remembers a failed resolution for a short window, so
// repeated dials while the resolver is broken fail fast.
func (r *bootstrapResolver) storeFailure(host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[host] = cacheEntry{
		err:     err,
		expires: time.Now().Add(bootstrapNegativeTTL),
	}
}
