// Package dnsfake provides a fake plain-DNS upstream for tests: UDP
// and TCP listeners on one 127.0.0.1 port, a settable per-query handler
// and an atomic query counter. It exists only for tests; production
// code must not import it.
package dnsfake

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// maxPortAttempts bounds the retries when another process grabs the
// UDP port that was picked for the TCP listener.
const maxPortAttempts = 10

// Fake is a fake plain DNS upstream listening on 127.0.0.1, UDP and
// TCP on the same port. The zero value is not usable; call New.
type Fake struct {
	udpConn net.PacketConn
	tcpLn   net.Listener
	udpSrv  *dns.Server
	tcpSrv  *dns.Server

	mu      sync.RWMutex // guards handler
	handler func(*dns.Msg) *dns.Msg

	calls atomic.Int64
}

// New starts the fake on 127.0.0.1: a TCP listener picks a free port
// and the UDP socket binds to the same port number, so both protocols
// share one address. In the rare case the UDP port is taken in
// between, a fresh port is tried, up to 10 times.
func New() (*Fake, error) {
	var lastErr error
	for i := 0; i < maxPortAttempts; i++ {
		tcpLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			lastErr = err
			continue
		}
		port := tcpLn.Addr().(*net.TCPAddr).Port
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			tcpLn.Close()
			lastErr = err
			continue // the UDP port was taken; try another port
		}

		f := &Fake{udpConn: udpConn, tcpLn: tcpLn}
		f.udpSrv = &dns.Server{PacketConn: udpConn, Handler: f}
		f.tcpSrv = &dns.Server{Listener: tcpLn, Handler: f}
		go f.udpSrv.ActivateAndServe()
		go f.tcpSrv.ActivateAndServe()
		return f, nil
	}
	return nil, fmt.Errorf("dnsfake: find a port for both UDP and TCP after %d attempts: %w", maxPortAttempts, lastErr)
}

// Addr returns the fake's listen address, "127.0.0.1:<port>",
// reachable over both UDP and TCP.
func (f *Fake) Addr() string {
	return f.tcpLn.Addr().String()
}

// SetHandler sets the handler applied to every received query. The
// handler returns the reply message; the fake fills in the request's
// ID before sending it, so handlers do not need to copy the ID
// themselves. Returning nil sends no reply: the client sees a
// timeout. SetHandler is safe to call between queries.
func (f *Fake) SetHandler(h func(*dns.Msg) *dns.Msg) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = h
}

// Calls returns the number of queries received so far, UDP and TCP
// combined.
func (f *Fake) Calls() int {
	return int(f.calls.Load())
}

// Close stops both listeners and waits until their serve loops have
// ended. The underlying sockets are closed first so the loops always
// exit, even if they have not started serving yet. Close is safe to
// call more than once.
func (f *Fake) Close() {
	f.udpConn.Close()
	f.tcpLn.Close()
	f.udpSrv.Shutdown()
	f.tcpSrv.Shutdown()
}

// ServeDNS implements dns.Handler for both listeners: it counts the
// query, applies the current handler and writes the reply with the
// request's ID.
func (f *Fake) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	f.calls.Add(1)

	f.mu.RLock()
	h := f.handler
	f.mu.RUnlock()
	if h == nil {
		h = defaultHandler
	}

	resp := h(req)
	if resp == nil {
		return // no reply: the client times out
	}
	resp.Id = req.Id
	_ = w.WriteMsg(resp)
}

// defaultHandler is the handler used until SetHandler is called: a
// NOERROR reply echoing the question, with no answers.
func defaultHandler(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	return m
}
