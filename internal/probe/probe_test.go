package probe_test

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/testutil/dnsfake"
)

// newFakeEndpoint starts a fake plain server delaying answers by delay
// and returns the matching endpoint.
func newFakeEndpoint(t *testing.T, delay time.Duration) providers.Endpoint {
	t.Helper()

	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)
	fake.SetHandler(func(req *dns.Msg) *dns.Msg {
		if delay > 0 {
			time.Sleep(delay)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		return m
	})
	return providers.Endpoint{Transport: "plain", Address: fake.Addr()}
}

// TestMeasurePlain checks the happy path: an answering endpoint gets a
// latency and no error.
func TestMeasurePlain(t *testing.T) {
	ep := newFakeEndpoint(t, 0)

	got := probe.Measure(context.Background(), []providers.Endpoint{ep}, probe.Options{})
	if len(got) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(got))
	}
	if got[0].Err != "" {
		t.Fatalf("Err = %q, want empty", got[0].Err)
	}
	if got[0].Latency <= 0 {
		t.Errorf("Latency = %v, want > 0", got[0].Latency)
	}
	if got[0].Endpoint != ep {
		t.Errorf("Endpoint = %+v, want %+v", got[0].Endpoint, ep)
	}
}

// TestMeasureErrors checks that unreachable endpoints report an error
// without affecting others.
func TestMeasureErrors(t *testing.T) {
	good := newFakeEndpoint(t, 0)
	bad := providers.Endpoint{Transport: "plain", Address: "127.0.0.1:1"}

	got := probe.Measure(context.Background(), []providers.Endpoint{bad, good}, probe.Options{Timeout: time.Second})
	if got[0].Err == "" {
		t.Errorf("bad endpoint Err = empty, want a connection error")
	}
	if got[1].Err != "" {
		t.Errorf("good endpoint Err = %q, want empty", got[1].Err)
	}
}

// TestMeasureTimeout checks that a silent endpoint times out quickly.
func TestMeasureTimeout(t *testing.T) {
	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)
	fake.SetHandler(func(*dns.Msg) *dns.Msg { return nil }) // stay silent

	ep := providers.Endpoint{Transport: "plain", Address: fake.Addr()}
	start := time.Now()
	got := probe.Measure(context.Background(), []providers.Endpoint{ep}, probe.Options{Timeout: 100 * time.Millisecond})
	elapsed := time.Since(start)

	if got[0].Err == "" {
		t.Fatalf("Err = empty, want a timeout error")
	}
	if elapsed >= time.Second {
		t.Errorf("Measure took %v, want under a second", elapsed)
	}
}

// TestMeasureParallel checks that slow endpoints are measured
// concurrently: six 100ms endpoints complete well under their serial
// time.
func TestMeasureParallel(t *testing.T) {
	eps := make([]providers.Endpoint, 6)
	for i := range eps {
		eps[i] = newFakeEndpoint(t, 100*time.Millisecond)
	}

	start := time.Now()
	got := probe.Measure(context.Background(), eps, probe.Options{Parallel: 6, Timeout: 2 * time.Second})
	elapsed := time.Since(start)

	for i, r := range got {
		if r.Err != "" {
			t.Fatalf("endpoint #%d Err = %q, want empty", i, r.Err)
		}
	}
	if elapsed >= 400*time.Millisecond {
		t.Errorf("Measure took %v, want < 400ms (endpoints run in parallel)", elapsed)
	}
}

// TestMeasureOrder checks that results follow the input order.
func TestMeasureOrder(t *testing.T) {
	slow := newFakeEndpoint(t, 50*time.Millisecond)
	fast := newFakeEndpoint(t, 0)
	bad := providers.Endpoint{Transport: "plain", Address: "127.0.0.1:1"}

	eps := []providers.Endpoint{slow, bad, fast}
	got := probe.Measure(context.Background(), eps, probe.Options{Timeout: time.Second})

	for i := range eps {
		if got[i].Endpoint != eps[i] {
			t.Errorf("results[%d].Endpoint = %+v, want %+v", i, got[i].Endpoint, eps[i])
		}
	}
}
