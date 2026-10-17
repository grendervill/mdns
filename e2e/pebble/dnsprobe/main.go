// Command dnsprobe sends one DNS query over DNS-over-TLS or
// DNS-over-QUIC to the server under test, verifies the served
// certificate against a CA bundle and prints the answer.
//
// The pebble e2e uses it for the DoT and DoQ checks when kdig is
// unavailable for the job: pebble issues certificates whose subject DN
// is empty (its default profile does not promote a common name), and
// GnuTLS — the TLS stack behind kdig — refuses to complete a handshake
// with them ("the name in the certificate does not match the
// expected" / "PKI verification of server certificate failed") even
// with pinning or +tls-hostname. OpenSSL, curl and Go's crypto/tls all
// accept the same certificate, so the probe talks to the daemon with
// the standard library and checks the chain the same way a real DoT or
// DoQ client would.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"mydns/internal/doq"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dnsprobe:", err)
		os.Exit(1)
	}
}

func run() error {
	proto := flag.String("proto", "dot", "protocol: dot or doq")
	server := flag.String("server", "daemon:853", "server address, host:port")
	name := flag.String("name", "example.com", "name to resolve")
	caFile := flag.String("ca", "", "PEM bundle the server certificate must chain to")
	serverName := flag.String("servername", "mdns.test", "name the certificate is verified against")
	timeout := flag.Duration("timeout", 10*time.Second, "overall deadline")
	flag.Parse()

	switch *proto {
	case "dot", "doq":
	default:
		return fmt.Errorf("unknown protocol %q (want dot or doq)", *proto)
	}
	if *caFile == "" {
		return fmt.Errorf("-ca is required")
	}

	pemBytes, err := os.ReadFile(*caFile)
	if err != nil {
		return fmt.Errorf("read CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("no certificates in %s", *caFile)
	}

	tlsCfg := &tls.Config{RootCAs: roots, ServerName: *serverName}
	if *proto == "dot" {
		tlsCfg.NextProtos = []string{"dot"}
	} else {
		tlsCfg.NextProtos = []string{"doq"}
	}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(*name), dns.TypeA)
	req.RecursionDesired = true
	packed, err := req.Pack()
	if err != nil {
		return fmt.Errorf("pack query: %w", err)
	}

	var raw []byte
	switch *proto {
	case "dot":
		raw, err = overTLS(*server, tlsCfg, packed, *timeout)
	default:
		raw, err = overQUIC(*server, tlsCfg, packed, *timeout)
	}
	if err != nil {
		return err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(raw); err != nil {
		return fmt.Errorf("unpack reply: %w", err)
	}
	for _, rr := range resp.Answer {
		fmt.Printf("  %s\n", rr.String())
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("reply rcode %s", dns.RcodeToString[resp.Rcode])
	}
	var answers int
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.To4() != nil {
			answers++
		}
	}
	if answers == 0 {
		return fmt.Errorf("reply carries no A record")
	}
	fmt.Printf("%s: certificate for %s verified, %d A record(s) for %s\n",
		*proto, *serverName, answers, strings.TrimSuffix(*name, "."))
	return nil
}

// overTLS runs one length-prefixed query over DNS-over-TLS (RFC 7858).
func overTLS(server string, cfg *tls.Config, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", server, cfg)
	if err != nil {
		return nil, fmt.Errorf("dot dial %s: %w", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := doq.WriteMessage(conn, query); err != nil {
		return nil, fmt.Errorf("dot write: %w", err)
	}
	raw, err := doq.ReadMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("dot read: %w", err)
	}
	return raw, nil
}

// overQUIC runs one length-prefixed query over DNS-over-QUIC (RFC 9250).
func overQUIC(server string, cfg *tls.Config, query []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, server, cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("doq dial %s: %w", server, err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq stream: %w", err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(timeout))

	if err := doq.WriteMessage(stream, query); err != nil {
		return nil, fmt.Errorf("doq write: %w", err)
	}
	raw, err := doq.ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("doq read: %w", err)
	}
	return raw, nil
}
