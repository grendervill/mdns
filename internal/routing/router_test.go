package routing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/routing"
	"mydns/internal/testutil/scripted"
	"mydns/internal/upstream"
)

// newScriptedUpstream builds an enabled upstream whose transport
// replies through f.
func newScriptedUpstream(t *testing.T, id string, priority int, f func(*dns.Msg) (*dns.Msg, error)) (*upstream.Upstream, *scripted.Transport) {
	t.Helper()

	tr := scripted.New()
	tr.SetReply(f)
	u := upstream.NewWithTransport(config.UpstreamConfig{
		ID:        id,
		Name:      id,
		Transport: "plain",
		Address:   "127.0.0.1:53",
		Priority:  priority,
		Enabled:   true,
	}, tr)
	return u, tr
}

// answer builds a NOERROR reply with the question echoed.
func answer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	return m
}

// query builds a single-question A query.
func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

// TestRouterFailsOverOnError checks that a transport error moves the
// query to the next upstream, without retrying the failed one.
func TestRouterFailsOverOnError(t *testing.T) {
	bad, badTr := newScriptedUpstream(t, "bad", 0, func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("dial refused")
	})
	good, _ := newScriptedUpstream(t, "good", 1, func(req *dns.Msg) (*dns.Msg, error) {
		return answer(req), nil
	})

	r, err := routing.New([]*upstream.Upstream{bad, good}, "failover")
	if err != nil {
		t.Fatalf("routing.New() = %v, want nil", err)
	}

	resp, used, err := r.Exchange(context.Background(), query("example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if used != good {
		t.Errorf("Exchange() used %q, want %q", used.ID, good.ID)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Exchange() reply = %v, want a NOERROR reply", resp)
	}
	if got := badTr.Calls(); got != 1 {
		t.Errorf("failed upstream calls = %d, want 1 (no retry)", got)
	}
}

// TestRouterFailsOverOnSERVFAIL checks that a SERVFAIL from one
// upstream moves the query to the next.
func TestRouterFailsOverOnSERVFAIL(t *testing.T) {
	sick, _ := newScriptedUpstream(t, "sick", 0, func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		return m, nil
	})
	good, _ := newScriptedUpstream(t, "good", 1, func(req *dns.Msg) (*dns.Msg, error) {
		m := answer(req)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   nil,
		})
		return m, nil
	})

	r, _ := routing.New([]*upstream.Upstream{sick, good}, "failover")
	resp, used, err := r.Exchange(context.Background(), query("example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if used != good {
		t.Errorf("Exchange() used %q, want %q", used.ID, good.ID)
	}
	if resp == nil || len(resp.Answer) != 1 {
		t.Errorf("Exchange() reply has %d answers, want 1 from the healthy upstream", len(resp.Answer))
	}
}

// TestRouterSlowUpstreamDoesNotBlock checks failover timing: when the
// first upstream is slow and fails, the answer arrives from the second
// well before the overall context would expire.
func TestRouterSlowUpstreamDoesNotBlock(t *testing.T) {
	slow, _ := newScriptedUpstream(t, "slow", 0, func(*dns.Msg) (*dns.Msg, error) {
		time.Sleep(100 * time.Millisecond)
		return nil, errors.New("upstream timed out")
	})
	good, _ := newScriptedUpstream(t, "good", 1, func(req *dns.Msg) (*dns.Msg, error) {
		return answer(req), nil
	})

	r, _ := routing.New([]*upstream.Upstream{slow, good}, "failover")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, used, err := r.Exchange(ctx, query("example.com"))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if used != good {
		t.Errorf("Exchange() used %q, want %q", used.ID, good.ID)
	}
	if elapsed >= 250*time.Millisecond {
		t.Errorf("Exchange() took %v, want to fail over without waiting out the 300ms context", elapsed)
	}
}

// TestRouterDoesNotFailoverOnNXDOMAIN checks that a NXDOMAIN is a
// final answer, not a reason to try the next upstream.
func TestRouterDoesNotFailoverOnNXDOMAIN(t *testing.T) {
	first, _ := newScriptedUpstream(t, "first", 0, func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		return m, nil
	})
	second, secondTr := newScriptedUpstream(t, "second", 1, func(req *dns.Msg) (*dns.Msg, error) {
		return answer(req), nil
	})

	r, _ := routing.New([]*upstream.Upstream{first, second}, "failover")
	resp, used, err := r.Exchange(context.Background(), query("missing.example.com"))
	if err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}
	if used != first {
		t.Errorf("Exchange() used %q, want %q", used.ID, first.ID)
	}
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Errorf("Exchange() reply = %v, want NXDOMAIN", resp)
	}
	if got := secondTr.Calls(); got != 0 {
		t.Errorf("second upstream calls = %d, want 0 (NXDOMAIN is final)", got)
	}
}

// TestRouterAllFailReturnsError checks that an exhausted list returns
// an error rather than an empty reply.
func TestRouterAllFailReturnsError(t *testing.T) {
	a, _ := newScriptedUpstream(t, "a", 0, func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("a down")
	})
	b, _ := newScriptedUpstream(t, "b", 1, func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("b down")
	})

	r, _ := routing.New([]*upstream.Upstream{a, b}, "failover")
	resp, used, err := r.Exchange(context.Background(), query("example.com"))
	if err == nil {
		t.Fatalf("Exchange() = nil error, want an error")
	}
	if resp != nil || used != nil {
		t.Errorf("Exchange() = (%v, %v), want (nil, nil)", resp, used)
	}
}

// TestRouterNoUpstreams checks the empty router.
func TestRouterNoUpstreams(t *testing.T) {
	r, err := routing.New(nil, "fastest")
	if err != nil {
		t.Fatalf("routing.New(nil) = %v, want nil", err)
	}
	if _, _, err := r.Exchange(context.Background(), query("example.com")); err == nil {
		t.Errorf("Exchange() = nil error, want a no-upstreams error")
	}
}

// TestRouterUnknownStrategy checks that an unknown strategy name is
// rejected at construction.
func TestRouterUnknownStrategy(t *testing.T) {
	if r, err := routing.New(nil, "bogus"); err == nil || r != nil {
		t.Errorf("routing.New(bogus) = (%v, %v), want (nil, error)", r, err)
	}
}
