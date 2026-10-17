package dnsserver

import (
	"net/http"
	"testing"
)

// TestDoHServersHardened checks that the DoH servers carry the
// timeouts and header bounds an internet-facing endpoint needs
// (Slowloris protection and connection hygiene).
func TestDoHServersHardened(t *testing.T) {
	httpSrv, h3Srv := buildDoHServers(http.NewServeMux(), nil, ":0")

	if httpSrv.ReadHeaderTimeout <= 0 {
		t.Errorf("HTTPS ReadHeaderTimeout = 0, want > 0 (Slowloris protection)")
	}
	if httpSrv.ReadTimeout <= 0 {
		t.Errorf("HTTPS ReadTimeout = 0, want > 0")
	}
	if httpSrv.WriteTimeout <= 0 {
		t.Errorf("HTTPS WriteTimeout = 0, want > 0")
	}
	if httpSrv.IdleTimeout <= 0 {
		t.Errorf("HTTPS IdleTimeout = 0, want > 0")
	}
	if httpSrv.MaxHeaderBytes <= 0 {
		t.Errorf("HTTPS MaxHeaderBytes = 0, want > 0")
	}
	if h3Srv.IdleTimeout <= 0 {
		t.Errorf("HTTP/3 IdleTimeout = 0, want > 0")
	}
	if h3Srv.MaxHeaderBytes <= 0 {
		t.Errorf("HTTP/3 MaxHeaderBytes = 0, want > 0")
	}
}
