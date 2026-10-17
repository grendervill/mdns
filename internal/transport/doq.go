package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"mydns/internal/config"
	"mydns/internal/doq"
)

// DoQ is an upstream over DNS-over-QUIC (RFC 9250). Queries are
// answered on one shared QUIC connection, one stream per query. When
// the server closes the connection, the next query dials a fresh one.
type DoQ struct {
	addr      string
	tlsConfig *tls.Config

	mu   sync.Mutex
	conn *quic.Conn
}

// newDoQ builds the DoQ transport from cfg. The SNI comes from
// cfg.ServerName; when that is empty, the address's host is used.
// cfg.InsecureSkipVerify passes through for self-signed upstreams.
func newDoQ(cfg config.UpstreamConfig) *DoQ {
	serverName := cfg.ServerName
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(cfg.Address)
	}

	return &DoQ{
		addr: cfg.Address,
		tlsConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			NextProtos:         []string{"doq"},
		},
	}
}

// Name implements Transport.
func (q *DoQ) Name() string { return "doq" }

// Exchange implements Transport. When the shared connection turns out
// to be dead between queries, it dials once more and repeats the query;
// a timeout on a live connection is never retried.
func (q *DoQ) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, err := q.roundTrip(ctx, req)
	if err != nil && ctx.Err() == nil && q.connDead() {
		resp, err = q.roundTrip(ctx, req)
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// roundTrip sends one query on a fresh stream of the shared connection
// and reads the reply.
func (q *DoQ) roundTrip(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	conn, err := q.connection(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq dial %s: %w", q.addr, err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq stream %s: %w", q.addr, err)
	}
	defer stream.Close()

	deadline := time.Now().Add(queryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)

	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("doq pack %s: %w", q.addr, err)
	}
	if err := doq.WriteMessage(stream, packed); err != nil {
		return nil, fmt.Errorf("doq write %s: %w", q.addr, err)
	}

	raw, err := doq.ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("doq read %s: %w", q.addr, err)
	}

	out := new(dns.Msg)
	if err := out.Unpack(raw); err != nil {
		return nil, fmt.Errorf("doq unpack %s: %w", q.addr, err)
	}
	return out, nil
}

// connection returns the shared QUIC connection, dialing one when none
// exists or the previous one has died.
func (q *DoQ) connection(ctx context.Context) (*quic.Conn, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.conn != nil {
		if q.conn.Context().Err() == nil {
			return q.conn, nil
		}
		_ = q.conn.CloseWithError(0, "")
		q.conn = nil
	}

	conn, err := quic.DialAddr(ctx, q.addr, q.tlsConfig, nil)
	if err != nil {
		return nil, err
	}
	q.conn = conn
	return conn, nil
}

// connDead reports whether the shared connection is gone, which is the
// signal that a failed exchange is worth one retry on a fresh dial.
func (q *DoQ) connDead() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.conn == nil || q.conn.Context().Err() != nil
}

// Close implements Transport: it closes the shared connection.
func (q *DoQ) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.conn != nil {
		_ = q.conn.CloseWithError(0, "")
		q.conn = nil
	}
	return nil
}
