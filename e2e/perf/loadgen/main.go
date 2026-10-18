// Command loadgen generates DNS load for the perf harness.
//
// Two transports are supported: plain UDP (default) and DNS over HTTPS
// (-doh URL, RFC 8484 GET). The query mix is configurable and defaults to
// the harness mix: 70% warm cache names, 20% blocked names and 10% unique
// names (cache misses that reach the upstream).
//
// The process prints a human summary, then one machine-readable line:
//
//	PERF_JSON {"sent":...,"done":...,"errs":...,"elapsed_s":...,"qps":...,...}
//
// done counts successful answers, errs counts failed attempts (write,
// read, unpack or HTTP errors); sent counts attempts that were actually
// put on the wire. With a healthy daemon sent == done and errs == 0.
package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	addr     = flag.String("addr", "127.0.0.1:53", "plain DNS address")
	dohURL   = flag.String("doh", "", "if set, use DoH GET to this URL instead of plain DNS")
	workers  = flag.Int("workers", 64, "parallel workers")
	total    = flag.Int64("total", 0, "total queries (0 = use duration)")
	duration = flag.Duration("dur", 0, "duration instead of total")
	cacheSet = flag.Int("cache", 2000, "size of the warm cache-hit name set")
	blockSet = flag.Int("block", 500, "size of the blocked name set")
	cachePct = flag.Int("cachepct", 70, "percent cache-hit names")
	blockPct = flag.Int("blockpct", 20, "percent blocked names (rest unique)")
	prewarm  = flag.Bool("prewarm", true, "prewarm the cache-hit names over plain DNS")
)

var (
	sent, done, errs atomic.Int64
	claimed          atomic.Int64
	rcode            sync.Map // map[int]*int64
	hist             [10]atomic.Int64
	uniq             atomic.Uint64
	deadline         time.Time
	// runID namespaces the unique (cache-miss) names of this process, so
	// a repeat phase never accidentally reuses a warm name from the
	// previous one — the mix must stay honest at any scale.
	runID = time.Now().UnixNano()
)

var bucketNames = [10]string{
	"<1ms", "1-2ms", "2-5ms", "5-10ms", "10-25ms",
	"25-50ms", "50-100ms", "100-250ms", "250ms-1s", ">1s",
}

// bucket maps a latency to its histogram bucket.
func bucket(d time.Duration) int {
	ms := float64(d.Microseconds()) / 1000.0
	switch {
	case ms < 1:
		return 0
	case ms < 2:
		return 1
	case ms < 5:
		return 2
	case ms < 10:
		return 3
	case ms < 25:
		return 4
	case ms < 50:
		return 5
	case ms < 100:
		return 6
	case ms < 250:
		return 7
	case ms < 1000:
		return 8
	default:
		return 9
	}
}

// pickName returns the next query name for the configured mix.
func pickName(r *rand.Rand) string {
	switch p := r.Intn(100); {
	case p < *cachePct:
		return fmt.Sprintf("c%d.perf.test.", r.Intn(*cacheSet))
	case p < *cachePct+*blockPct:
		return fmt.Sprintf("blk%d.test.", r.Intn(*blockSet))
	default:
		return fmt.Sprintf("u%d-%d.perf.test.", runID, uniq.Add(1))
	}
}

func main() {
	flag.Parse()
	if *total <= 0 && *duration <= 0 {
		fmt.Fprintln(os.Stderr, "loadgen: need -total or -dur")
		os.Exit(2)
	}
	if *cachePct+*blockPct > 100 {
		fmt.Fprintln(os.Stderr, "loadgen: -cachepct + -blockpct must be <= 100")
		os.Exit(2)
	}

	prewarmed := 0
	if *dohURL == "" && *prewarm {
		n, err := prewarmCache()
		if err != nil {
			fmt.Fprintln(os.Stderr, "loadgen: prewarm:", err)
			os.Exit(1)
		}
		prewarmed = n
	}

	if *total <= 0 {
		deadline = time.Now().Add(*duration)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(time.Now().UnixNano() + seed))
			if *dohURL != "" {
				workerDoH(r)
			} else {
				workerUDP(r)
			}
		}(int64(i))
	}
	wg.Wait()
	elapsed := time.Since(start)

	summarize(elapsed, prewarmed)
	if errs.Load() > 0 {
		os.Exit(1)
	}
}

// claim reserves one query against the total (or the duration budget).
// It never overshoots the total.
func claim() bool {
	if *total > 0 {
		for {
			n := claimed.Load()
			if n >= *total {
				return false
			}
			if claimed.CompareAndSwap(n, n+1) {
				return true
			}
		}
	}
	return !time.Now().After(deadline)
}

func prewarmCache() (int, error) {
	conn, err := net.Dial("udp", *addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for i := 0; i < *cacheSet; i++ {
		m := new(dns.Msg)
		m.SetQuestion(fmt.Sprintf("c%d.perf.test.", i), dns.TypeA)
		m.Id = uint16(i%65000 + 1)
		raw, err := m.Pack()
		if err != nil {
			return i, err
		}
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return i, err
		}
		if _, err := conn.Write(raw); err != nil {
			return i, fmt.Errorf("write %d: %w", i, err)
		}
		if _, err := conn.Read(buf); err != nil {
			return i, fmt.Errorf("read %d: %w", i, err)
		}
	}
	return *cacheSet, nil
}

func workerUDP(r *rand.Rand) {
	conn, err := net.Dial("udp", *addr)
	if err != nil {
		errs.Add(1)
		return
	}
	defer conn.Close()

	buf := make([]byte, 1500)
	for claim() {
		m := new(dns.Msg)
		m.SetQuestion(pickName(r), dns.TypeA)
		m.Id = uint16(r.Intn(65000) + 1)
		raw, err := m.Pack()
		if err != nil {
			errs.Add(1)
			continue
		}

		sent.Add(1)
		t0 := time.Now()
		_ = conn.SetDeadline(t0.Add(2 * time.Second))
		if _, err := conn.Write(raw); err != nil {
			errs.Add(1)
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			errs.Add(1)
			continue
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(buf[:n]); err != nil {
			errs.Add(1)
			continue
		}
		done.Add(1)
		hist[bucket(time.Since(t0))].Add(1)
		incRcode(resp.Rcode)
	}
}

func workerDoH(r *rand.Rand) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	defer tr.CloseIdleConnections()

	for claim() {
		m := new(dns.Msg)
		m.SetQuestion(pickName(r), dns.TypeA)
		raw, err := m.Pack()
		if err != nil {
			errs.Add(1)
			continue
		}
		q := base64.RawURLEncoding.EncodeToString(raw)

		sent.Add(1)
		t0 := time.Now()
		req, err := http.NewRequest("GET", *dohURL+"?dns="+q, nil)
		if err != nil {
			errs.Add(1)
			continue
		}
		req.Header.Set("Accept", "application/dns-message")
		resp, err := cl.Do(req)
		if err != nil {
			errs.Add(1)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			errs.Add(1)
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			errs.Add(1)
			continue
		}
		done.Add(1)
		hist[bucket(time.Since(t0))].Add(1)
		incRcode(msg.Rcode)
	}
}

func incRcode(c int) {
	v, _ := rcode.LoadOrStore(c, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

// percentileBucket returns the bucket containing the given percentile of
// the successful responses.
func percentileBucket(p float64) string {
	n := done.Load()
	if n == 0 {
		return ""
	}
	want := int64(float64(n)*p + 0.999)
	var cum int64
	for i := range hist {
		cum += hist[i].Load()
		if cum >= want {
			return bucketNames[i]
		}
	}
	return bucketNames[len(bucketNames)-1]
}

func summarize(elapsed time.Duration, prewarmed int) {
	n := done.Load()
	qps := float64(n) / elapsed.Seconds()

	fmt.Printf("sent=%d done=%d errs=%d elapsed=%s qps=%.0f\n",
		sent.Load(), n, errs.Load(), elapsed.Round(time.Millisecond), qps)

	var cum int64
	for i := range hist {
		c := hist[i].Load()
		if c == 0 {
			continue
		}
		cum += c
		pct := 0.0
		if n > 0 {
			pct = 100 * float64(c) / float64(n)
		}
		fmt.Printf("  %-10s %10d  (%.2f%%)\n", bucketNames[i], c, pct)
	}

	rcodes := make([]int, 0, 4)
	rcode.Range(func(k, _ any) bool {
		rcodes = append(rcodes, k.(int))
		return true
	})
	sort.Ints(rcodes)
	parts := make([]string, 0, len(rcodes))
	for _, rc := range rcodes {
		v, _ := rcode.Load(rc)
		parts = append(parts, fmt.Sprintf("%s=%d", dns.RcodeToString[rc], *v.(*int64)))
	}
	fmt.Printf("rcodes: %v\n", parts)
	fmt.Printf("~p50 bucket: %s  ~p95 bucket: %s\n", percentileBucket(0.50), percentileBucket(0.95))

	buckets := make(map[string]int64, len(bucketNames))
	for i := range hist {
		if c := hist[i].Load(); c > 0 {
			buckets[bucketNames[i]] = c
		}
	}
	mode := "udp"
	if *dohURL != "" {
		mode = "doh"
	}
	rec := struct {
		Mode      string           `json:"mode"`
		Sent      int64            `json:"sent"`
		Done      int64            `json:"done"`
		Errs      int64            `json:"errs"`
		ElapsedS  float64          `json:"elapsed_s"`
		QPS       float64          `json:"qps"`
		Workers   int              `json:"workers"`
		Prewarmed int              `json:"prewarmed"`
		P50Bucket string           `json:"p50_bucket"`
		P95Bucket string           `json:"p95_bucket"`
		Buckets   map[string]int64 `json:"buckets"`
	}{
		Mode:      mode,
		Sent:      sent.Load(),
		Done:      n,
		Errs:      errs.Load(),
		ElapsedS:  elapsed.Seconds(),
		QPS:       qps,
		Workers:   *workers,
		Prewarmed: prewarmed,
		P50Bucket: percentileBucket(0.50),
		P95Bucket: percentileBucket(0.95),
		Buckets:   buckets,
	}

	fmt.Print("PERF_JSON ")
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		fmt.Fprintln(os.Stderr, "loadgen: marshal summary:", err)
	}
}
