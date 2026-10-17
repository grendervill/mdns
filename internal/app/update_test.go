package app_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mydns/internal/app"
	"mydns/internal/config"
)

// startApp starts an app with the given config and a persisted config
// file, returning the app and the config path.
func startApp(t *testing.T, cfg *config.Config) (*app.App, string) {
	t.Helper()

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("cfg.Save() = %v, want nil", err)
	}

	a, err := app.New(cfg, app.Options{Monitor: fastMonitor(), ConfigPath: cfgPath}, discardLogger())
	if err != nil {
		t.Fatalf("app.New() = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := a.Start(ctx); err != nil {
		t.Fatalf("Start() = %v, want nil", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = a.Stop(sctx)
	})
	return a, cfgPath
}

// TestUpdateConfigSoft checks the soft path: strategy and cache changes
// apply without restarting listeners - an already-open TCP connection
// keeps answering.
func TestUpdateConfigSoft(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	a, cfgPath := startApp(t, cfg)

	// Open a plain-TCP connection before the update.
	conn, err := net.Dial("tcp", loopback(port))
	if err != nil {
		t.Fatalf("Dial() = %v, want nil", err)
	}
	defer conn.Close()

	next := *cfg
	next.Strategy = "failover"
	next.Cache.MaxTTL = 3600

	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	// The old connection must still answer: listeners were not
	// restarted.
	dc := &dns.Conn{Conn: conn}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if err := dc.WriteMsg(q); err != nil {
		t.Fatalf("WriteMsg on the old connection = %v, want nil", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := dc.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg on the old connection = %v, want nil (listeners must stay up)", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %d, want NOERROR", resp.Rcode)
	}

	// The change persisted.
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	if loaded.Strategy != "failover" || loaded.Cache.MaxTTL != 3600 {
		t.Errorf("persisted config = strategy %q max_ttl %d, want failover/3600", loaded.Strategy, loaded.Cache.MaxTTL)
	}
}

// TestUpdateConfigStructural checks the structural path: a port change
// rebinds listeners and persists.
func TestUpdateConfigStructural(t *testing.T) {
	fake := newFakeUpstream(t)
	oldPort := freePort(t)
	newPort := freePort(t)
	cfg := testConfig(t, fake, oldPort)
	a, cfgPath := startApp(t, cfg)

	next := *cfg
	next.Protocols.Plain.Port = newPort

	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	// The new port answers.
	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := cl.Exchange(query("example.com"), loopback(newPort)); err != nil {
		t.Fatalf("Exchange on the new port = %v, want nil", err)
	}

	// The old port is closed: the query fails.
	oldCl := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	if _, _, err := oldCl.Exchange(query("example.com"), loopback(oldPort)); err == nil {
		t.Errorf("old port still answers, want it closed")
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	if loaded.Protocols.Plain.Port != newPort {
		t.Errorf("persisted port = %d, want %d", loaded.Protocols.Plain.Port, newPort)
	}
}

// TestUpdateConfigBindFailureRollsBack checks Review Focus #1: when the
// new port is taken, the error is clear, the old listeners keep
// working and the config file is untouched.
func TestUpdateConfigBindFailureRollsBack(t *testing.T) {
	fake := newFakeUpstream(t)
	oldPort := freePort(t)
	cfg := testConfig(t, fake, oldPort)
	a, cfgPath := startApp(t, cfg)

	busy, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatalf("ListenPacket() = %v, want nil", err)
	}
	defer busy.Close()
	busyPort := busy.LocalAddr().(*net.UDPAddr).Port

	next := *cfg
	next.Protocols.Plain.Port = busyPort

	if err := a.UpdateConfig(context.Background(), &next); err == nil {
		t.Fatalf("UpdateConfig(busy port) = nil, want an error")
	}

	// The old listener still answers.
	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := cl.Exchange(query("example.com"), loopback(oldPort)); err != nil {
		t.Fatalf("Exchange on the old port = %v, want nil (rolled back)", err)
	}

	// The config file kept the old port.
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	if loaded.Protocols.Plain.Port != oldPort {
		t.Errorf("persisted port = %d, want the old %d", loaded.Protocols.Plain.Port, oldPort)
	}
}

// TestUpdateConfigInvalid checks that an invalid config changes
// nothing.
func TestUpdateConfigInvalid(t *testing.T) {
	fake := newFakeUpstream(t)
	port := freePort(t)
	cfg := testConfig(t, fake, port)
	a, cfgPath := startApp(t, cfg)

	next := *cfg
	next.Domain = ""

	if err := a.UpdateConfig(context.Background(), &next); err == nil {
		t.Fatalf("UpdateConfig(invalid) = nil, want an error")
	}

	// Still serving on the old config.
	cl := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := cl.Exchange(query("example.com"), loopback(port)); err != nil {
		t.Fatalf("Exchange() = %v, want nil", err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load() = %v, want nil", err)
	}
	if loaded.Domain != cfg.Domain {
		t.Errorf("persisted domain = %q, want %q", loaded.Domain, cfg.Domain)
	}
}
