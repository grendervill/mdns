package main

import (
	"flag"
	"reflect"
	"strings"
	"testing"

	"mydns/internal/installer"
)

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

// TestInstallFlagsWire parses every documented install flag into the
// flag holder, so a typo in a name or a missing registration fails here
// instead of at a real installation.
func TestInstallFlagsWire(t *testing.T) {
	var f installFlags
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	installFlagSet(fs, &f)

	args := []string{
		"--non-interactive", "--dry-run", "--reconfigure",
		"--config", "/tmp/config.json", "--data-dir", "/tmp/data",
		"--domain", "dns.example.com", "--tls", "acme",
		"--acme-provider", "zerossl", "--acme-email", "admin@example.com",
		"--acme-directory", "https://ca.example.com/acme/directory", "--acme-insecure",
		"--eab-kid", "kid-1", "--eab-hmac", "hmac-secret",
		"--cert-file", "/etc/mdns/fullchain.pem", "--key-file", "/etc/mdns/privkey.pem",
		"--provider", "cloudflare", "--provider", "quad9",
		"--strategy", "failover",
		"--plain-port", "5353", "--doh-port", "8443", "--dot-port", "8853", "--doq-port", "8853",
		"--filter", "strict",
		"--panel", "--password", "s3cret-pass",
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse install flags: %v", err)
	}

	want := installFlags{
		NonInteractive: true,
		DryRun:         true,
		Reconfigure:    true,
		ConfigPath:     "/tmp/config.json",
		DataDir:        "/tmp/data",
		Domain:         "dns.example.com",
		TLSMode:        "acme",
		ACMEProvider:   "zerossl",
		ACMEEmail:      "admin@example.com",
		ACMEDirectory:  "https://ca.example.com/acme/directory",
		ACMEInsecure:   true,
		EABKid:         "kid-1",
		EABHMAC:        "hmac-secret",
		CertFile:       "/etc/mdns/fullchain.pem",
		KeyFile:        "/etc/mdns/privkey.pem",
		Providers:      []string{"cloudflare", "quad9"},
		Strategy:       "failover",
		PlainPort:      5353,
		DoHPort:        8443,
		DoTPort:        8853,
		DoQPort:        8853,
		FilterPreset:   "strict",
		Panel:          true,
		Password:       "s3cret-pass",
	}
	if !reflect.DeepEqual(f, want) {
		t.Errorf("parsed flags = %+v\nwant %+v", f, want)
	}
}

// TestInstallSpecFromFlags maps a fully specified flag set to the
// installer Spec, field for field.
func TestInstallSpecFromFlags(t *testing.T) {
	f := installFlags{
		NonInteractive: true,
		Domain:         " dns.example.com ",
		TLSMode:        "acme",
		ACMEProvider:   "custom",
		ACMEEmail:      "admin@example.com",
		ACMEDirectory:  "https://ca.internal/acme/directory",
		ACMEInsecure:   true,
		EABKid:         "kid-1",
		EABHMAC:        "hmac-secret",
		CertFile:       "/etc/mdns/fullchain.pem",
		KeyFile:        "/etc/mdns/privkey.pem",
		Providers:      []string{"cloudflare", "quad9"},
		Strategy:       "failover",
		PlainPort:      5353,
		DoHPort:        8443,
		DoTPort:        8853,
		DoQPort:        8853,
		FilterPreset:   "basic",
		Panel:          true,
		Password:       "s3cret-pass",
	}

	spec, err := installSpecFromFlags(f)
	if err != nil {
		t.Fatalf("installSpecFromFlags() error = %v, want nil", err)
	}
	panelOn := true
	want := &installer.Spec{
		Domain:        "dns.example.com",
		TLSMode:       "acme",
		ACMEProvider:  "custom",
		ACMEEmail:     "admin@example.com",
		ACMEDirectory: "https://ca.internal/acme/directory",
		ACMEInsecure:  true,
		EABKid:        "kid-1",
		EABHMAC:       "hmac-secret",
		CertFile:      "/etc/mdns/fullchain.pem",
		KeyFile:       "/etc/mdns/privkey.pem",
		Providers:     []string{"cloudflare", "quad9"},
		Strategy:      "failover",
		PlainPort:     5353,
		DoHPort:       8443,
		DoTPort:       8853,
		DoQPort:       8853,
		FilterPreset:  "basic",
		PanelPassword: "s3cret-pass",
		PanelEnabled:  &panelOn,
	}
	if !reflect.DeepEqual(spec, want) {
		t.Errorf("installSpecFromFlags() = %+v\nwant %+v", spec, want)
	}
}

// TestInstallSpecFromFlagsPanel pins the panel tristate of the flags:
// --no-panel forces off, --panel forces on and neither leaves the choice
// to --password.
func TestInstallSpecFromFlagsPanel(t *testing.T) {
	tests := []struct {
		name    string
		flags   installFlags
		want    *bool
		wantPwd string
	}{
		{
			name:    "no-panel forces off",
			flags:   installFlags{NonInteractive: true, Domain: "dns.example.com", NoPanel: true, Password: "s3cret-pass"},
			want:    boolPtr(false),
			wantPwd: "s3cret-pass",
		},
		{
			name:    "panel forces on",
			flags:   installFlags{NonInteractive: true, Domain: "dns.example.com", Panel: true},
			want:    boolPtr(true),
			wantPwd: "",
		},
		{
			name:    "neither defers to the password",
			flags:   installFlags{NonInteractive: true, Domain: "dns.example.com", Password: "s3cret-pass"},
			want:    nil,
			wantPwd: "s3cret-pass",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := installSpecFromFlags(tt.flags)
			if err != nil {
				t.Fatalf("installSpecFromFlags() error = %v, want nil", err)
			}
			if !reflect.DeepEqual(spec.PanelEnabled, tt.want) {
				t.Errorf("PanelEnabled = %v, want %v", spec.PanelEnabled, tt.want)
			}
			if spec.PanelPassword != tt.wantPwd {
				t.Errorf("PanelPassword = %q, want %q", spec.PanelPassword, tt.wantPwd)
			}
		})
	}
}

// boolPtr returns a pointer to v, for the panel tristate assertions.
func boolPtr(v bool) *bool { return &v }

// TestInstallSpecFromFlagsRequiresDomain checks the non-interactive
// contract: without a domain there is nothing to install, and the
// message says which flag is missing.
func TestInstallSpecFromFlagsRequiresDomain(t *testing.T) {
	spec, err := installSpecFromFlags(installFlags{
		NonInteractive: true,
		TLSMode:        "self-signed",
	})
	if err == nil {
		t.Fatalf("installSpecFromFlags() = %+v, want an error", spec)
	}
	if !strings.Contains(err.Error(), "domain") {
		t.Errorf("error = %q, want it to name the missing domain flag", err)
	}
}

// TestInstallSpecFromFlagsInteractive checks that the wizard path
// carries no Spec at all: the spec flags are ignored.
func TestInstallSpecFromFlagsInteractive(t *testing.T) {
	spec, err := installSpecFromFlags(installFlags{Domain: "dns.example.com", Providers: []string{"cloudflare"}})
	if err != nil {
		t.Fatalf("installSpecFromFlags() error = %v, want nil", err)
	}
	if spec != nil {
		t.Errorf("installSpecFromFlags() = %+v, want nil for the interactive path", spec)
	}
}

// TestConfirmUninstall checks the confirmation reader: yes wins, anything
// else (including an empty stream) declines.
func TestConfirmUninstall(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"yes\n", true},
		{" YES \n", true},
		{"да\n", true},
		{"n\n", false},
		{"\n", false},
		{"", false},
		{"y", true},
	}
	for _, tt := range tests {
		if got := confirmUninstall(strings.NewReader(tt.in)); got != tt.want {
			t.Errorf("confirmUninstall(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
