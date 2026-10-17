package main

import "testing"

// TestServeOptionsCarryPaths guards the serve wiring: without
// ConfigPath the daemon cannot persist configuration updates coming
// from the TUI, the wizard or the web panel.
func TestServeOptionsCarryPaths(t *testing.T) {
	opts := serveOptions("/etc/mdns/config.json", "/run/mdns/mdns.sock")

	if opts.ConfigPath != "/etc/mdns/config.json" {
		t.Errorf("ConfigPath = %q, want the serve --config value", opts.ConfigPath)
	}
	if opts.SocketPath != "/run/mdns/mdns.sock" {
		t.Errorf("SocketPath = %q, want the serve --socket value", opts.SocketPath)
	}
}
