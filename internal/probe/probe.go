// Package probe measures the latency of resolver endpoints: one "NS ."
// query per endpoint, run in parallel with a small worker pool.
package probe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/providers"
	"mydns/internal/transport"
)

// Result is one endpoint's probe outcome; Err is empty on success.
type Result struct {
	Endpoint providers.Endpoint
	Latency  time.Duration
	Err      string
}

// Options tune the probe run; zero values mean the defaults.
type Options struct {
	Parallel int           // 0 → 16
	Timeout  time.Duration // 0 → 2s per endpoint
}

// Measure probes every endpoint and returns the results in the input
// order. It never returns an error: failures land in each Result.
func Measure(ctx context.Context, eps []providers.Endpoint, opts Options) []Result {
	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 16
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	results := make([]Result, len(eps))
	sem := make(chan struct{}, parallel)

	var wg sync.WaitGroup
	for i, ep := range eps {
		wg.Add(1)
		go func(i int, ep providers.Endpoint) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = Result{Endpoint: ep, Err: ctx.Err().Error()}
				return
			}
			defer func() { <-sem }()

			results[i] = measureOne(ctx, ep, timeout)
		}(i, ep)
	}
	wg.Wait()
	return results
}

// measureOne sends the probe query through the endpoint's own
// transport, exactly as the server would talk to it.
func measureOne(ctx context.Context, ep providers.Endpoint, timeout time.Duration) Result {
	res := Result{Endpoint: ep}

	tr, err := transport.New(ep.UpstreamConfig("probe", "probe"))
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer tr.Close()

	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	q := new(dns.Msg)
	q.SetQuestion(".", dns.TypeNS)

	start := time.Now()
	resp, err := tr.Exchange(pctx, q)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if resp.Truncated || resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
		res.Err = fmt.Sprintf("unexpected reply: %s", dns.RcodeToString[resp.Rcode])
		return res
	}

	res.Latency = time.Since(start)
	return res
}
