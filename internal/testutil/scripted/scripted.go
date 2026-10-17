// Package scripted provides a hand-scripted Transport for tests:
// replies come from a settable function and every request is recorded.
// It exists only for tests; production code must not import it.
package scripted

import (
	"context"
	"fmt"
	"sync"

	"github.com/miekg/dns"
)

// Transport is a transport.Transport whose replies are scripted by the
// test. The zero value is usable; call SetReply before Exchange.
type Transport struct {
	mu    sync.Mutex
	reply func(*dns.Msg) (*dns.Msg, error)
	calls []*dns.Msg
}

// New returns an empty scripted transport.
func New() *Transport { return &Transport{} }

// SetReply installs the reply function. Without one, Exchange fails.
func (t *Transport) SetReply(f func(*dns.Msg) (*dns.Msg, error)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reply = f
}

// Name implements transport.Transport.
func (t *Transport) Name() string { return "scripted" }

// Exchange implements transport.Transport: it records the request and
// lets the scripted reply function produce the result.
func (t *Transport) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	t.mu.Lock()
	t.calls = append(t.calls, req.Copy())
	f := t.reply
	t.mu.Unlock()

	if f == nil {
		return nil, fmt.Errorf("scripted: no reply configured")
	}
	return f(req)
}

// Close implements transport.Transport.
func (t *Transport) Close() error { return nil }

// Calls returns how many exchanges were attempted.
func (t *Transport) Calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.calls)
}

// LastCall returns the most recent request, or nil if there was none.
func (t *Transport) LastCall() *dns.Msg {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.calls) == 0 {
		return nil
	}
	return t.calls[len(t.calls)-1]
}
