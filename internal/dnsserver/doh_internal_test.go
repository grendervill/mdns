package dnsserver

import (
	"net/http"
	"net/http/httptest"
	"slices"
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

// fakePanel records that it was mounted and adds one route, so the test
// can see the panel's patterns land on the DoH mux.
type fakePanel struct{ mounted bool }

func (f *fakePanel) Mount(mux *http.ServeMux) {
	f.mounted = true
	mux.HandleFunc("GET /panel/probe", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

// TestDoHMuxMountsPanel checks that a panel passed through SetPanel is
// mounted next to /dns-query, and that the DoH endpoint keeps working.
func TestDoHMuxMountsPanel(t *testing.T) {
	var s Server
	panel := &fakePanel{}
	s.SetPanel(panel)

	mux := s.dohMux()
	if !panel.mounted {
		t.Fatal("panel was not mounted on the DoH mux")
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/dns-query", nil))
	if rec.Code == http.StatusNotFound {
		t.Error("/dns-query is not routed when a panel is mounted")
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/probe", nil))
	if rec.Code != http.StatusNoContent {
		t.Errorf("panel route = %d, want 204", rec.Code)
	}
}

// TestDoHMuxWithoutPanel checks the default: no panel, /dns-query only.
func TestDoHMuxWithoutPanel(t *testing.T) {
	var s Server

	rec := httptest.NewRecorder()
	s.dohMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET / without a panel = %d, want 404", rec.Code)
	}
}

// TestDoHServersACMEALPN checks the RFC 8737 wiring: an ACME source
// puts acme-tls/1 next to h2 and http/1.1 on the HTTPS listener, while
// a plain source and the HTTP/3 server keep it out.
func TestDoHServersACMEALPN(t *testing.T) {
	httpSrv, h3Srv := buildDoHServers(http.NewServeMux(), &fakeSource{ready: true, acmeALPN: true}, ":443")

	protos := httpSrv.TLSConfig.NextProtos
	for _, want := range []string{"h2", "http/1.1", "acme-tls/1"} {
		if !slices.Contains(protos, want) {
			t.Errorf("HTTPS NextProtos = %v, want %q", protos, want)
		}
	}
	if slices.Contains(h3Srv.TLSConfig.NextProtos, "acme-tls/1") {
		t.Errorf("HTTP/3 NextProtos = %v, want no acme-tls/1", h3Srv.TLSConfig.NextProtos)
	}

	plain, _ := buildDoHServers(http.NewServeMux(), &fakeSource{ready: true}, ":443")
	if slices.Contains(plain.TLSConfig.NextProtos, "acme-tls/1") {
		t.Errorf("plain source NextProtos = %v, want no acme-tls/1", plain.TLSConfig.NextProtos)
	}
}
