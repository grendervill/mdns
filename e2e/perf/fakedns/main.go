// Command fakedns is a fast local upstream resolver for the perf harness.
//
// It answers every A/AAAA question with a fixed documentation address and
// counts the queries it served. The count is printed on SIGINT/SIGTERM, so
// the harness can compare what the daemon says it sent (status.Upstreams)
// with what the upstream actually received.
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/miekg/dns"
)

func main() {
	addr := "127.0.0.1:53530"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	var served atomic.Uint64

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		served.Add(1)
		m := new(dns.Msg)
		m.SetReply(req)
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(192, 0, 2, 1),
				})
			case dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
					AAAA: net.ParseIP("2001:db8::1"),
				})
			}
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{Addr: addr, Net: "udp", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintln(os.Stderr, "fakedns:", err)
			os.Exit(1)
		}
	}()
	fmt.Fprintf(os.Stderr, "fakedns listening on %s\n", addr)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch

	fmt.Printf("fakedns served: %d\n", served.Load())
}
