package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/testutil/dnsfake"
)

// newFakeEndpoint starts a fake plain server and returns its endpoint.
func newFakeEndpoint(t *testing.T) providers.Endpoint {
	t.Helper()
	fake, err := dnsfake.New()
	if err != nil {
		t.Fatalf("dnsfake.New() = %v, want nil", err)
	}
	t.Cleanup(fake.Close)
	fake.SetHandler(func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		return m
	})
	return providers.Endpoint{Transport: "plain", Address: fake.Addr()}
}

// postJSON sends a JSON POST and returns the response.
func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s = %v, want nil", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// putJSON sends a JSON PUT and returns the response.
func putJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s = %v, want nil", url, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestProbeEndpoint checks that probe requests reach the controller
// with the endpoints intact and real measurements come back in order.
func TestProbeEndpoint(t *testing.T) {
	ep1 := newFakeEndpoint(t)
	ep2 := newFakeEndpoint(t)

	ctl := &fakeController{
		probeFn: func(ctx context.Context, eps []providers.Endpoint) []probe.Result {
			return probe.Measure(ctx, eps, probe.Options{Timeout: time.Second})
		},
	}
	ts := newTestServer(t, ctl)

	body := map[string]any{
		"endpoints": []map[string]string{
			{"transport": ep1.Transport, "address": ep1.Address},
			{"transport": ep2.Transport, "address": ep2.Address},
		},
	}
	resp := postJSON(t, ts.URL+"/api/v1/probe", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var got struct {
		Results []probe.Result `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(got.Results))
	}
	if got.Results[0].Endpoint.Address != ep1.Address || got.Results[1].Endpoint.Address != ep2.Address {
		t.Errorf("results order = [%s %s], want [%s %s]",
			got.Results[0].Endpoint.Address, got.Results[1].Endpoint.Address, ep1.Address, ep2.Address)
	}
	for i, r := range got.Results {
		if r.Err != "" || r.Latency <= 0 {
			t.Errorf("result #%d = %+v, want a successful measurement", i, r)
		}
	}
}

// TestPutConfigApplied checks that a valid config reaches the
// controller.
func TestPutConfigApplied(t *testing.T) {
	ctl := &fakeController{}
	ts := newTestServer(t, ctl)

	cfg := config.Default()
	cfg.Domain = "new.example.com"

	resp := putJSON(t, ts.URL+"/api/v1/config", cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ctl.lastConfig == nil || ctl.lastConfig.Domain != "new.example.com" {
		t.Errorf("controller saw %+v, want the new config", ctl.lastConfig)
	}
}

// TestPutConfigInvalid checks validation happens before the controller.
func TestPutConfigInvalid(t *testing.T) {
	ctl := &fakeController{}
	ts := newTestServer(t, ctl)

	cfg := config.Default()
	cfg.Domain = "" // invalid

	resp := putJSON(t, ts.URL+"/api/v1/config", cfg)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if ctl.lastConfig != nil {
		t.Errorf("controller was called with %+v, want no call", ctl.lastConfig)
	}
}

// TestPutConfigError checks that an application error surfaces with its
// text.
func TestPutConfigError(t *testing.T) {
	ctl := &fakeController{updateErr: errors.New("bind: address in use")}
	ts := newTestServer(t, ctl)

	resp := putJSON(t, ts.URL+"/api/v1/config", config.Default())
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body["error"], "address in use") {
		t.Errorf("error = %q, want the controller's text", body["error"])
	}
}

// TestFilterUpdateViaAPI checks the manual list update endpoint.
func TestFilterUpdateViaAPI(t *testing.T) {
	ctl := &fakeController{}
	ts := newTestServer(t, ctl)

	resp := postJSON(t, ts.URL+"/api/v1/filter/update", map[string]string{"id": "oisd-small"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ctl.lastFilterID != "oisd-small" {
		t.Errorf("FilterUpdate(%q), want oisd-small", ctl.lastFilterID)
	}
}
