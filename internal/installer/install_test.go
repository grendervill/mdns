package installer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"mydns/internal/auth"
	"mydns/internal/config"
	"mydns/internal/filter"
)

// checkCall is one recorded Runner invocation.
type checkCall struct {
	name string
	args []string
}

// fakeRunner records every call and answers canned outputs: an exact
// "name args..." key from responses, otherwise a success without output
// when the command name is in ok, otherwise an error. Tests assert on
// the recorded calls, so nothing reaches the system.
type fakeRunner struct {
	responses map[string][]byte
	ok        map[string]bool
	calls     []checkCall
}

// newFakeRunner returns a runner that fails every unregistered command.
func newFakeRunner() *fakeRunner {
	return &fakeRunner{responses: map[string][]byte{}, ok: map[string]bool{}}
}

func (f *fakeRunner) run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, checkCall{name: name, args: args})
	key := strings.Join(append([]string{name}, args...), " ")
	if out, ok := f.responses[key]; ok {
		return out, nil
	}
	if f.ok[name] {
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command %q", key)
}

// commands renders every recorded call for assertions and messages.
func (f *fakeRunner) commands() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, strings.Join(append([]string{c.name}, c.args...), " "))
	}
	return out
}

// ufwAllows returns the ports of the recorded "ufw allow" calls.
func (f *fakeRunner) ufwAllows() []string {
	var out []string
	for _, c := range f.calls {
		if c.name == "ufw" && len(c.args) == 2 && c.args[0] == "allow" {
			out = append(out, c.args[1])
		}
	}
	return out
}

// serviceRestarts counts the recorded "systemctl restart mdns" calls.
func (f *fakeRunner) serviceRestarts() int {
	n := 0
	for _, c := range f.calls {
		if c.name == "systemctl" && slices.Equal(c.args, []string{"restart", "mdns"}) {
			n++
		}
	}
	return n
}

// noChecks is the preflight seam of the action tests: the real checks
// inspect the process euid and the host system, which a temporary Root
// cannot satisfy.
func noChecks(Options) []Check { return nil }

// installFixture builds a Root, a source binary and a runner that
// accepts systemctl and ufw with ufw active. The service reports active,
// so the post-restart success check passes.
func installFixture(t *testing.T) (root, binarySource string, runner *fakeRunner) {
	t.Helper()
	root = t.TempDir()
	binarySource = filepath.Join(t.TempDir(), "mdns")
	if err := os.WriteFile(binarySource, []byte("fake mdns binary"), 0o755); err != nil {
		t.Fatalf("write binary source: %v", err)
	}
	runner = newFakeRunner()
	runner.ok["systemctl"] = true
	runner.ok["ufw"] = true
	runner.responses["ufw status"] = []byte("Status: active\n")
	runner.responses["systemctl is-active mdns"] = []byte("active\n")
	return root, binarySource, runner
}

// assertNotExist fails when path exists.
func assertNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("%s exists (stat error %v), want no such file", path, err)
	}
}

// assertMode fails unless path has the wanted permission bits.
func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}

// TestRenderUnitGolden pins the exact systemd unit, byte for byte.
func TestRenderUnitGolden(t *testing.T) {
	got := renderUnit("/usr/local/bin/mdns", "/etc/mdns/config.json")
	want := "[Unit]\n" +
		"Description=mdns — self-hosted DNS service\n" +
		"After=network-online.target\n" +
		"Wants=network-online.target\n" +
		"\n" +
		"[Service]\n" +
		"ExecStart=/usr/local/bin/mdns serve --config /etc/mdns/config.json\n" +
		"Restart=always\n" +
		"RestartSec=2\n" +
		"LimitNOFILE=65536\n" +
		"\n" +
		"[Install]\n" +
		"WantedBy=multi-user.target\n"
	if got != want {
		t.Errorf("renderUnit() =\n%q\nwant\n%q", got, want)
	}
	if !strings.HasSuffix(got, "multi-user.target\n") {
		t.Errorf("renderUnit() has no trailing newline: %q", got)
	}
}

// TestBuildConfigFull maps a fully specified Spec to every config field.
func TestBuildConfigFull(t *testing.T) {
	spec := Spec{
		Domain:        "dns.example.com",
		TLSMode:       "acme",
		ACMEProvider:  "custom",
		ACMEEmail:     "admin@example.com",
		ACMEDirectory: "https://ca.internal/acme/directory",
		ACMEInsecure:  true,
		EABKid:        "kid-1",
		EABHMAC:       "hmac-secret",
		Providers:     []string{"cloudflare", "quad9"},
		Strategy:      "failover",
		PlainPort:     5353,
		DoHPort:       8443,
		DoTPort:       8853,
		DoQPort:       8853,
		FilterPreset:  "strict",
	}

	cfg, err := buildConfig(spec)
	if err != nil {
		t.Fatalf("buildConfig() error = %v, want nil", err)
	}

	if cfg.Domain != spec.Domain {
		t.Errorf("Domain = %q, want %q", cfg.Domain, spec.Domain)
	}
	if cfg.TLS.Mode != "acme" {
		t.Errorf("TLS.Mode = %q, want acme", cfg.TLS.Mode)
	}
	wantACME := config.ACME{
		Provider:           "custom",
		Email:              "admin@example.com",
		DirectoryURL:       "https://ca.internal/acme/directory",
		EABKeyID:           "kid-1",
		EABHMAC:            "hmac-secret",
		InsecureSkipVerify: true,
	}
	if cfg.TLS.ACME != wantACME {
		t.Errorf("TLS.ACME = %+v, want %+v", cfg.TLS.ACME, wantACME)
	}
	if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		t.Errorf("TLS cert/key = %q/%q, want empty in acme mode", cfg.TLS.CertFile, cfg.TLS.KeyFile)
	}

	for _, p := range []struct {
		name string
		got  config.Protocol
		port int
	}{
		{"plain", cfg.Protocols.Plain, 5353},
		{"doh", cfg.Protocols.DoH, 8443},
		{"dot", cfg.Protocols.DoT, 8853},
		{"doq", cfg.Protocols.DoQ, 8853},
	} {
		if !p.got.Enabled || p.got.Port != p.port {
			t.Errorf("protocols.%s = %+v, want enabled on %d", p.name, p.got, p.port)
		}
	}

	if cfg.Strategy != "failover" {
		t.Errorf("Strategy = %q, want failover", cfg.Strategy)
	}

	wantUpstreams := []config.UpstreamConfig{
		{
			ID:        "cloudflare",
			Name:      "Cloudflare",
			Transport: "doh",
			Address:   "https://cloudflare-dns.com/dns-query",
			Priority:  1,
			Enabled:   true,
		},
		{
			ID:        "quad9",
			Name:      "Quad9",
			Transport: "doh",
			Address:   "https://dns.quad9.net/dns-query",
			Priority:  2,
			Enabled:   true,
		},
	}
	if !slices.Equal(cfg.Upstreams, wantUpstreams) {
		t.Errorf("Upstreams = %+v, want %+v", cfg.Upstreams, wantUpstreams)
	}

	if !cfg.Filter.Enabled {
		t.Errorf("Filter.Enabled = false, want true for the strict preset")
	}
	ids, ok := filter.Preset("strict")
	if !ok {
		t.Fatal(`filter.Preset("strict") = not found`)
	}
	gotIDs := make([]string, 0, len(cfg.Filter.Lists))
	for _, l := range cfg.Filter.Lists {
		gotIDs = append(gotIDs, l.ID)
	}
	if !slices.Equal(gotIDs, ids) {
		t.Errorf("Filter.Lists = %v, want %v", gotIDs, ids)
	}
}

// TestBuildConfigDefaults pins the defaults of a domain-only Spec.
func TestBuildConfigDefaults(t *testing.T) {
	cfg, err := buildConfig(Spec{Domain: "dns.example.com"})
	if err != nil {
		t.Fatalf("buildConfig() error = %v, want nil", err)
	}

	if cfg.Domain != "dns.example.com" {
		t.Errorf("Domain = %q, want dns.example.com", cfg.Domain)
	}
	if cfg.TLS.Mode != "self-signed" {
		t.Errorf("TLS.Mode = %q, want self-signed", cfg.TLS.Mode)
	}
	if cfg.TLS.ACME != (config.ACME{}) {
		t.Errorf("TLS.ACME = %+v, want the zero value", cfg.TLS.ACME)
	}
	if cfg.Strategy != "fastest" {
		t.Errorf("Strategy = %q, want fastest", cfg.Strategy)
	}

	for _, p := range []struct {
		name string
		got  config.Protocol
		port int
	}{
		{"plain", cfg.Protocols.Plain, 53},
		{"doh", cfg.Protocols.DoH, 443},
		{"dot", cfg.Protocols.DoT, 853},
		{"doq", cfg.Protocols.DoQ, 853},
	} {
		if !p.got.Enabled || p.got.Port != p.port {
			t.Errorf("protocols.%s = %+v, want enabled on %d", p.name, p.got, p.port)
		}
	}

	wantUpstreams := []config.UpstreamConfig{{
		ID:        "cloudflare",
		Name:      "Cloudflare",
		Transport: "doh",
		Address:   "https://cloudflare-dns.com/dns-query",
		Priority:  1,
		Enabled:   true,
	}}
	if !slices.Equal(cfg.Upstreams, wantUpstreams) {
		t.Errorf("Upstreams = %+v, want %+v", cfg.Upstreams, wantUpstreams)
	}

	if cfg.Filter.Enabled {
		t.Errorf("Filter.Enabled = true, want false by default")
	}
	if len(cfg.Filter.Lists) != 0 {
		t.Errorf("Filter.Lists = %+v, want none by default", cfg.Filter.Lists)
	}
	if cfg.Filter.Mode != "zero" {
		t.Errorf("Filter.Mode = %q, want zero", cfg.Filter.Mode)
	}
	if cfg.DataDir != "/var/lib/mdns" {
		t.Errorf("DataDir = %q, want /var/lib/mdns", cfg.DataDir)
	}
	if cfg.Version != 1 {
		t.Errorf("Version = %d, want 1", cfg.Version)
	}
}

// TestBuildConfigFileMode checks the files TLS mode: the certificate
// paths are required.
func TestBuildConfigFileMode(t *testing.T) {
	cfg, err := buildConfig(Spec{
		Domain:   "dns.example.com",
		TLSMode:  "files",
		CertFile: "/etc/mdns/fullchain.pem",
		KeyFile:  "/etc/mdns/privkey.pem",
	})
	if err != nil {
		t.Fatalf("buildConfig() error = %v, want nil", err)
	}
	if cfg.TLS.Mode != "files" || cfg.TLS.CertFile != "/etc/mdns/fullchain.pem" || cfg.TLS.KeyFile != "/etc/mdns/privkey.pem" {
		t.Errorf("TLS = %+v, want files with the given paths", cfg.TLS)
	}
}

// TestBuildConfigPanelHash checks the panel password: it is hashed, the
// hash verifies against the plaintext and the serialized config never
// carries the plaintext.
func TestBuildConfigPanelHash(t *testing.T) {
	const pw = "hunter2hunter2"

	cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelPassword: pw})
	if err != nil {
		t.Fatalf("buildConfig() error = %v, want nil", err)
	}
	if !cfg.Panel.Enabled {
		t.Fatalf("Panel.Enabled = false, want true")
	}
	if !strings.HasPrefix(cfg.Panel.PasswordHash, "$argon2id$") {
		t.Errorf("PasswordHash = %q, want an argon2id PHC hash", cfg.Panel.PasswordHash)
	}
	if !auth.Verify(cfg.Panel.PasswordHash, pw) {
		t.Errorf("the stored hash does not verify %q", pw)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if strings.Contains(string(data), pw) {
		t.Errorf("the serialized config leaks the plaintext password:\n%s", data)
	}
}

// TestBuildConfigPanelFlagBehavior pins the panel tristate: an explicit
// --panel needs a password, a password turns the panel on by itself, and
// neither leaves it off.
func TestBuildConfigPanelFlagBehavior(t *testing.T) {
	on := true
	off := false

	t.Run("panel without a password", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelEnabled: &on})
		if err == nil {
			t.Fatalf("buildConfig() = %+v, want an error", cfg)
		}
		if !strings.Contains(err.Error(), "password") {
			t.Errorf("error = %q, want it to name the missing password", err)
		}
	})

	t.Run("password turns the panel on", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelPassword: "longenough"})
		if err != nil {
			t.Fatalf("buildConfig() error = %v, want nil", err)
		}
		if !cfg.Panel.Enabled {
			t.Errorf("Panel.Enabled = false, want true when a password is set")
		}
	})

	t.Run("neither leaves the panel off", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com"})
		if err != nil {
			t.Fatalf("buildConfig() error = %v, want nil", err)
		}
		if cfg.Panel.Enabled || cfg.Panel.PasswordHash != "" {
			t.Errorf("Panel = %+v, want it off by default", cfg.Panel)
		}
	})

	t.Run("no-panel wins over a password", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelEnabled: &off, PanelPassword: "longenough"})
		if err != nil {
			t.Fatalf("buildConfig() error = %v, want nil", err)
		}
		if cfg.Panel.Enabled {
			t.Errorf("Panel.Enabled = true, want --no-panel to win")
		}
	})

	t.Run("password too short", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelPassword: "short"})
		if err == nil {
			t.Fatalf("buildConfig() = %+v, want an error", cfg)
		}
		if !strings.Contains(err.Error(), "8") {
			t.Errorf("error = %q, want it to name the minimum length", err)
		}
	})

	t.Run("whitespace-only password is rejected", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelPassword: "        "})
		if err == nil {
			t.Fatalf("buildConfig() = %+v, want an error", cfg)
		}
		if !strings.Contains(err.Error(), "whitespace") {
			t.Errorf("error = %q, want it to name the whitespace", err)
		}
	})

	t.Run("surrounding whitespace is rejected", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelPassword: "longenough "})
		if err == nil {
			t.Fatalf("buildConfig() = %+v, want an error", cfg)
		}
		if !strings.Contains(err.Error(), "whitespace") {
			t.Errorf("error = %q, want it to name the whitespace", err)
		}
	})
}

// TestInstallSummaryPanelLine checks the summary's panel line in both
// states.
func TestInstallSummaryPanelLine(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		cfg, err := buildConfig(Spec{Domain: "dns.example.com", PanelPassword: "longenough"})
		if err != nil {
			t.Fatalf("buildConfig() error = %v, want nil", err)
		}
		var out bytes.Buffer
		printSummary(&out, cfg, "/usr/local/bin/mdns", "/etc/systemd/system/mdns.service", false)
		text := out.String()
		for _, want := range []string{
			"Панель: https://dns.example.com/ · логин admin",
			"пароль задан при установке",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("summary misses %q:\n%s", want, text)
			}
		}
		if strings.Contains(text, "Веб-панель выключена") {
			t.Errorf("summary claims the panel is off while it is on:\n%s", text)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		cfg := config.Default()
		cfg.Domain = "dns.example.com"
		var out bytes.Buffer
		printSummary(&out, cfg, "/usr/local/bin/mdns", "/etc/systemd/system/mdns.service", true)
		if !strings.Contains(out.String(), "Веб-панель выключена (--panel --password, чтобы включить)") {
			t.Errorf("summary misses the disabled-panel note:\n%s", out.String())
		}
	})
}

// TestBuildConfigInvalid rejects specs that cannot produce a valid
// config, with a message that names the problem.
func TestBuildConfigInvalid(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
		want string
	}{
		{
			name: "empty domain",
			spec: Spec{},
			want: "domain",
		},
		{
			name: "domain with a path",
			spec: Spec{Domain: "dns.example.com/path"},
			want: "domain",
		},
		{
			name: "unknown provider",
			spec: Spec{Domain: "dns.example.com", Providers: []string{"no-such-resolver"}},
			want: "unknown provider",
		},
		{
			name: "unknown tls mode",
			spec: Spec{Domain: "dns.example.com", TLSMode: "bogus"},
			want: "tls",
		},
		{
			name: "files without paths",
			spec: Spec{Domain: "dns.example.com", TLSMode: "files"},
			want: "cert",
		},
		{
			name: "acme without email",
			spec: Spec{Domain: "dns.example.com", TLSMode: "acme"},
			want: "email",
		},
		{
			name: "custom acme without directory",
			spec: Spec{Domain: "dns.example.com", TLSMode: "acme", ACMEProvider: "custom", ACMEEmail: "a@example.com"},
			want: "directory_url",
		},
		{
			name: "unknown acme provider",
			spec: Spec{Domain: "dns.example.com", TLSMode: "acme", ACMEProvider: "no-such-ca", ACMEEmail: "a@example.com"},
			want: "acme",
		},
		{
			name: "unknown filter preset",
			spec: Spec{Domain: "dns.example.com", FilterPreset: "paranoid"},
			want: "preset",
		},
		{
			name: "unknown strategy",
			spec: Spec{Domain: "dns.example.com", Strategy: "telepathy"},
			want: "strategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := buildConfig(tt.spec)
			if err == nil {
				t.Fatalf("buildConfig(%+v) = %+v, want an error", tt.spec, cfg)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("buildConfig(%+v) error = %q, want it to mention %q", tt.spec, err, tt.want)
			}
		})
	}
}

// TestBuildConfigInvalidRunWritesNothing checks that an invalid spec
// fails a non-interactive Run before the first byte reaches the disk.
func TestBuildConfigInvalidRunWritesNothing(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "mdns-src")
	if err := os.WriteFile(source, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write binary source: %v", err)
	}
	runner := newFakeRunner()
	var out bytes.Buffer

	err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    noChecks,
		BinarySource: source,
		Spec:         &Spec{Domain: "dns.example.com", Providers: []string{"no-such-resolver"}},
		Output:       &out,
	})
	if err == nil {
		t.Fatalf("Run() = nil, want an invalid-spec error")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("Run() error = %q, want it to mention the unknown provider", err)
	}

	for _, p := range []string{"etc", "etc/mdns/config.json", "usr/local/bin/mdns", "var/lib/mdns", "etc/systemd/system/mdns.service"} {
		assertNotExist(t, filepath.Join(root, p))
	}
	if len(runner.calls) != 0 {
		t.Errorf("Run() ran commands %v, want none", runner.commands())
	}
}

// TestInstallDryRun checks that the dry run prints the plan, prints the
// warnings of the checks and changes nothing.
func TestInstallDryRun(t *testing.T) {
	root := t.TempDir()
	runner := newFakeRunner() // any command would fail
	checks := func(Options) []Check {
		return []Check{
			{Name: "dns-a-record", Warning: true, Detail: "A/AAAA не указывает на этот сервер"},
			{Name: "ports", OK: true, Detail: "порты свободны: 53, 443, 853"},
		}
	}
	spec := Spec{Domain: "dns.example.com", TLSMode: "acme", ACMEEmail: "admin@example.com"}

	var out bytes.Buffer
	err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    checks,
		BinarySource: filepath.Join(root, "src-mdns"),
		DryRun:       true,
		Spec:         &spec,
		Output:       &out,
	})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if len(runner.calls) != 0 {
		t.Errorf("dry run ran commands %v, want none", runner.commands())
	}
	for _, p := range []string{"etc", "etc/mdns/config.json", "usr/local/bin/mdns", "var/lib/mdns", "etc/systemd/system/mdns.service"} {
		assertNotExist(t, filepath.Join(root, p))
	}

	text := out.String()
	for _, want := range []string{
		"План установки (DryRun)",
		"создать каталог",
		"скопировать бинарник",
		"конфигурация",
		"записать юнит",
		"systemctl daemon-reload; systemctl enable mdns; systemctl restart mdns",
		"ufw",
		"A/AAAA не указывает на этот сервер",
		"dns.example.com",
		"(DryRun)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dry-run output does not contain %q:\n%s", want, text)
		}
	}
}

// TestInstallWritesAndStarts checks the full non-interactive install:
// directories, the binary, the config, the unit and the service
// commands.
func TestInstallWritesAndStarts(t *testing.T) {
	root, source, runner := installFixture(t)
	spec := Spec{Domain: "dns.example.com", FilterPreset: "basic"}

	var out bytes.Buffer
	err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    noChecks,
		BinarySource: source,
		Spec:         &spec,
		Output:       &out,
	})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	assertMode(t, filepath.Join(root, "etc/mdns"), 0o755)
	assertMode(t, filepath.Join(root, "var/lib/mdns"), 0o700)

	binaryPath := filepath.Join(root, "usr/local/bin/mdns")
	got, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("read installed binary: %v", err)
	}
	if string(got) != "fake mdns binary" {
		t.Errorf("installed binary = %q, want the source content", got)
	}
	assertMode(t, binaryPath, 0o755)

	configPath := filepath.Join(root, "etc/mdns/config.json")
	assertMode(t, configPath, 0o600)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load installed config: %v", err)
	}
	if cfg.Domain != "dns.example.com" {
		t.Errorf("installed Domain = %q, want dns.example.com", cfg.Domain)
	}
	if want := filepath.Join(root, "var/lib/mdns"); cfg.DataDir != want {
		t.Errorf("installed DataDir = %q, want %q", cfg.DataDir, want)
	}
	if ids, _ := filter.Preset("basic"); !cfg.Filter.Enabled || len(cfg.Filter.Lists) != len(ids) {
		t.Errorf("installed filter = %+v, want the basic preset enabled", cfg.Filter)
	}

	unitPath := filepath.Join(root, "etc/systemd/system/mdns.service")
	unitBytes, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	if want := renderUnit(binaryPath, configPath); string(unitBytes) != want {
		t.Errorf("unit =\n%q\nwant\n%q", unitBytes, want)
	}
	assertMode(t, unitPath, 0o644)

	cmds := runner.commands()
	wantCmds := []string{"systemctl daemon-reload", "systemctl enable mdns", "systemctl restart mdns", "systemctl is-active mdns", "ufw status"}
	if len(cmds) < len(wantCmds) || !slices.Equal(cmds[:len(wantCmds)], wantCmds) {
		t.Errorf("commands = %v, want %v first", cmds, wantCmds)
	}
	// --now is a no-op on an active unit: the service state must be
	// applied with an explicit restart instead.
	for _, c := range cmds {
		if strings.Contains(c, "--now") {
			t.Errorf("command %q uses --now, want enable + restart", c)
		}
	}
	wantRules := []string{"53/tcp", "53/udp", "443/tcp", "443/udp", "853/tcp", "853/udp"}
	if got := runner.ufwAllows(); !slices.Equal(got, wantRules) {
		t.Errorf("ufw rules = %v, want %v", got, wantRules)
	}

	text := out.String()
	for _, want := range []string{
		"dns.example.com",
		"Ссылки для устройств",
		"Cloudflare",
		"Стратегия: fastest",
		"Фильтрация: включена",
		"Установлено: бинарник " + binaryPath,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("install output does not contain %q:\n%s", want, text)
		}
	}
}

// TestUFURulesEnabled checks the exact rules for a config with every
// protocol enabled and ACME with DoH off port 443: HTTP-01 needs 80/tcp.
func TestUFURulesEnabled(t *testing.T) {
	t.Run("acme with a non-443 DoH port", func(t *testing.T) {
		root, source, runner := installFixture(t)
		spec := Spec{
			Domain:       "dns.example.com",
			TLSMode:      "acme",
			ACMEEmail:    "admin@example.com",
			DoHPort:      8443,
			FilterPreset: "",
		}
		var out bytes.Buffer
		if err := Run(InstallOptions{
			Options:      Options{Root: root, Runner: runner.run},
			preflight:    noChecks,
			BinarySource: source,
			Spec:         &spec,
			Output:       &out,
		}); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}

		want := []string{"53/tcp", "53/udp", "8443/tcp", "8443/udp", "80/tcp", "853/tcp", "853/udp"}
		if got := runner.ufwAllows(); !slices.Equal(got, want) {
			t.Errorf("ufw rules = %v, want %v", got, want)
		}
		var first *checkCall
		for i, c := range runner.calls {
			if c.name == "ufw" {
				first = &runner.calls[i]
				break
			}
		}
		if first == nil || !slices.Equal(first.args, []string{"status"}) {
			t.Errorf("first ufw call = %+v, want the status probe", first)
		}
	})

	t.Run("acme with DoH on 443 needs no HTTP-01", func(t *testing.T) {
		root, source, runner := installFixture(t)
		spec := Spec{Domain: "dns.example.com", TLSMode: "acme", ACMEEmail: "admin@example.com"}
		var out bytes.Buffer
		if err := Run(InstallOptions{
			Options:      Options{Root: root, Runner: runner.run},
			preflight:    noChecks,
			BinarySource: source,
			Spec:         &spec,
			Output:       &out,
		}); err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if got := runner.ufwAllows(); slices.Contains(got, "80/tcp") {
			t.Errorf("ufw rules = %v, want no 80/tcp with DoH on 443", got)
		}
	})

	t.Run("self-signed needs no HTTP-01", func(t *testing.T) {
		cfg := config.Default()
		cfg.TLS.Mode = "self-signed"
		if got := ufwRules(cfg); slices.Contains(got, "80/tcp") {
			t.Errorf("ufwRules(self-signed) = %v, want no 80/tcp", got)
		}
	})
}

// TestUFURulesInactive checks that an inactive ufw gets the manual
// instruction and no allow calls.
func TestUFURulesInactive(t *testing.T) {
	root, source, runner := installFixture(t)
	runner.responses["ufw status"] = []byte("Status: inactive\n")
	spec := Spec{Domain: "dns.example.com"}

	var out bytes.Buffer
	if err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    noChecks,
		BinarySource: source,
		Spec:         &spec,
		Output:       &out,
	}); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if got := runner.ufwAllows(); len(got) != 0 {
		t.Errorf("ufw allow calls = %v, want none with ufw inactive", got)
	}
	text := out.String()
	for _, want := range []string{"ufw неактивен", "sudo ufw allow 53/tcp", "sudo ufw allow 853/udp"} {
		if !strings.Contains(text, want) {
			t.Errorf("output does not contain %q:\n%s", want, text)
		}
	}
}

// TestIdempotentKeepsConfig checks that an existing config survives a
// non-interactive run, and that --reconfigure replaces it.
func TestIdempotentKeepsConfig(t *testing.T) {
	root, source, runner := installFixture(t)
	configPath := filepath.Join(root, "etc/mdns/config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	old := config.Default()
	old.Domain = "old.example.com"
	if err := old.Save(configPath); err != nil {
		t.Fatalf("save existing config: %v", err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read existing config: %v", err)
	}
	beforeInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat existing config: %v", err)
	}

	spec := Spec{Domain: "new.example.com"}
	var out bytes.Buffer
	if err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    noChecks,
		BinarySource: source,
		Spec:         &spec,
		Output:       &out,
	}); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read kept config: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("kept config changed:\nbefore %s\nafter  %s", before, after)
	}
	afterInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat kept config: %v", err)
	}
	if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
		t.Errorf("kept config mtime = %v, want %v", afterInfo.ModTime(), beforeInfo.ModTime())
	}
	if !strings.Contains(out.String(), "оставлен без изменений") {
		t.Errorf("output does not mention the kept config:\n%s", out.String())
	}
	// The summary describes the config that stays, not the spec.
	if !strings.Contains(out.String(), "old.example.com") {
		t.Errorf("output does not describe the existing config:\n%s", out.String())
	}
	// The unit and the binary are still refreshed.
	if _, err := os.Stat(filepath.Join(root, "usr/local/bin/mdns")); err != nil {
		t.Errorf("binary not installed next to the kept config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/mdns.service")); err != nil {
		t.Errorf("unit not installed next to the kept config: %v", err)
	}
	// A re-run over the running service restarts it, so the refreshed
	// binary (and the unit) actually take effect.
	if got := runner.serviceRestarts(); got != 1 {
		t.Errorf("restart calls after the re-run = %d, want 1: %v", got, runner.commands())
	}

	// --reconfigure overwrites it.
	restarts := runner.serviceRestarts()
	var reconfigure bytes.Buffer
	if err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    noChecks,
		BinarySource: source,
		Spec:         &spec,
		Reconfigure:  true,
		Output:       &reconfigure,
	}); err != nil {
		t.Fatalf("Run(--reconfigure) error = %v, want nil", err)
	}
	// The rewritten config reaches the daemon through the restart.
	if got := runner.serviceRestarts(); got != restarts+1 {
		t.Errorf("restart calls after --reconfigure = %d, want %d", got, restarts+1)
	}
	loaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load reconfigured config: %v", err)
	}
	if loaded.Domain != "new.example.com" {
		t.Errorf("reconfigured Domain = %q, want new.example.com", loaded.Domain)
	}
}

// TestCheckPortsFor pins the derivation of the preflight port list:
// HTTP-01 binds :80 exactly when ACME has no DoH listener on 443 to carry
// TLS-ALPN-01.
func TestCheckPortsFor(t *testing.T) {
	acme := func(c *config.Config) *config.Config {
		c.TLS = config.TLS{Mode: "acme", ACME: config.ACME{Provider: "letsencrypt", Email: "a@example.com"}}
		return c
	}
	tests := []struct {
		name   string
		cfg    *config.Config
		want80 bool
	}{
		{
			name:   "acme with a non-443 DoH port needs 80",
			cfg:    acme(func() *config.Config { c := config.Default(); c.Protocols.DoH.Port = 8443; return c }()),
			want80: true,
		},
		{
			name:   "acme with DoH disabled needs 80",
			cfg:    acme(func() *config.Config { c := config.Default(); c.Protocols.DoH.Enabled = false; return c }()),
			want80: true,
		},
		{
			name: "acme with DoH on 443 needs no 80",
			cfg:  acme(config.Default()),
		},
		{
			name: "self-signed needs no 80",
			cfg:  func() *config.Config { c := config.Default(); c.TLS.Mode = "self-signed"; return c }(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkPortsFor(tt.cfg)
			if has80 := slices.Contains(got, 80); has80 != tt.want80 {
				t.Errorf("checkPortsFor(%+v) = %v, contains 80 = %v, want %v", tt.cfg.Protocols, got, has80, tt.want80)
			}
		})
	}
}

// TestRunPreflightChecksHTTP01Port checks that Run feeds the derived port
// list (with :80) to the preflight when ACME will use HTTP-01.
func TestRunPreflightChecksHTTP01Port(t *testing.T) {
	root, source, runner := installFixture(t)
	var gotPorts []int
	checks := func(o Options) []Check {
		gotPorts = o.BindPorts
		return nil
	}
	spec := Spec{Domain: "dns.example.com", TLSMode: "acme", ACMEEmail: "a@example.com", DoHPort: 8443}

	var out bytes.Buffer
	if err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    checks,
		BinarySource: source,
		Spec:         &spec,
		Output:       &out,
	}); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if !slices.Contains(gotPorts, 80) {
		t.Errorf("preflight BindPorts = %v, want it to include :80 for HTTP-01", gotPorts)
	}
}

// TestKeptInvalidConfigFails checks that a kept config is validated before
// any unit or service action: an invalid file aborts the run, names the
// path and suggests --reconfigure, and the service is never restarted.
func TestKeptInvalidConfigFails(t *testing.T) {
	root, source, runner := installFixture(t)
	configPath := filepath.Join(root, "etc/mdns/config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	bad := config.Default()
	bad.Domain = "" // Validate rejects an empty domain
	if err := bad.Save(configPath); err != nil {
		t.Fatalf("save invalid config: %v", err)
	}

	var out bytes.Buffer
	err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    noChecks,
		BinarySource: source,
		Spec:         &Spec{Domain: "dns.example.com"},
		Output:       &out,
	})
	if err == nil {
		t.Fatalf("Run() = nil, want an invalid kept-config error")
	}
	if !strings.Contains(err.Error(), configPath) {
		t.Errorf("Run() error = %q, want it to name %s", err, configPath)
	}
	if !strings.Contains(err.Error(), "--reconfigure") {
		t.Errorf("Run() error = %q, want it to suggest --reconfigure", err)
	}
	if got := runner.serviceRestarts(); got != 0 {
		t.Errorf("restart calls = %d, want 0 before the invalid config is caught: %v", got, runner.commands())
	}
	// The check precedes the unit write, so no unit is left behind.
	assertNotExist(t, filepath.Join(root, "etc/systemd/system/mdns.service"))
}

// TestServiceNotActiveFails checks that the installer does not report
// success when the unit is not actually up after the restart: a state
// other than "active" (or a failing systemctl) ends the run with an error
// naming the logs and no success summary.
func TestServiceNotActiveFails(t *testing.T) {
	old := serviceActiveInterval
	serviceActiveInterval = time.Millisecond
	t.Cleanup(func() { serviceActiveInterval = old })

	tests := []struct {
		name  string
		state string
		fail  bool
	}{
		{name: "activating", state: "activating"},
		{name: "is-active fails", fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, source, runner := installFixture(t)
			if tt.fail {
				delete(runner.responses, "systemctl is-active mdns")
			} else {
				runner.responses["systemctl is-active mdns"] = []byte(tt.state + "\n")
			}
			run := func(name string, args ...string) ([]byte, error) {
				if tt.fail && name == "systemctl" && slices.Equal(args, []string{"is-active", "mdns"}) {
					return nil, errors.New("systemctl is-active: Unit mdns.service could not be found")
				}
				return runner.run(name, args...)
			}
			spec := Spec{Domain: "dns.example.com"}

			var out bytes.Buffer
			err := Run(InstallOptions{
				Options:      Options{Root: root, Runner: run},
				preflight:    noChecks,
				BinarySource: source,
				Spec:         &spec,
				Output:       &out,
			})
			if err == nil {
				t.Fatalf("Run() = nil, want an error when the service is not active")
			}
			if !strings.Contains(err.Error(), "mdns не запустилась") {
				t.Errorf("Run() error = %q, want it to say the service did not start", err)
			}
			if !strings.Contains(err.Error(), "journalctl -u mdns") {
				t.Errorf("Run() error = %q, want it to point at the journal", err)
			}
			if got := runner.serviceRestarts(); got != 1 {
				t.Errorf("restart calls = %d, want 1", got)
			}
			if strings.Contains(out.String(), "Установлено: бинарник") {
				t.Errorf("output claims success although the service is not up:\n%s", out.String())
			}
		})
	}
}

// TestRunAbortsOnPreflightFailure checks the real preflight gate: an
// empty Root fails the systemd check and nothing is written. The
// resolve seams are stubbed so the A/AAAA check does not touch the
// network (the fixed domain would otherwise reach a live lookup).
func TestRunAbortsOnPreflightFailure(t *testing.T) {
	root := t.TempDir()
	runner := newFakeRunner()
	var out bytes.Buffer

	err := Run(InstallOptions{
		Options: Options{
			Root:         root,
			Runner:       runner.run,
			ResolveFn:    func(string) ([]string, error) { return []string{"198.51.100.9"}, nil },
			LocalAddrsFn: func() []string { return []string{"198.51.100.9"} },
		},
		Spec:   &Spec{Domain: "dns.example.com"},
		Output: &out,
	})
	if err == nil {
		t.Fatalf("Run() with an empty Root = nil, want a preflight error")
	}
	if !strings.Contains(err.Error(), "systemd") {
		t.Errorf("Run() error = %q, want it to name the failed systemd check", err)
	}
	for _, p := range []string{"etc", "etc/mdns", "usr/local/bin", "var/lib/mdns", "etc/systemd/system/mdns.service"} {
		assertNotExist(t, filepath.Join(root, p))
	}
}

// TestRunPreflightUsesSpecDomain checks that the non-interactive run
// passes the spec's domain to the checks: the A/AAAA check is skipped
// with an empty domain, so a mismatch must surface as a warning for
// that domain.
func TestRunPreflightUsesSpecDomain(t *testing.T) {
	root, source, runner := installFixture(t)

	const domain = "dns.example.com"
	var checkedDomain string
	checks := func(o Options) []Check {
		checkedDomain = o.Domain
		return []Check{checkARecord(o)}
	}

	spec := Spec{Domain: domain}
	var out bytes.Buffer
	err := Run(InstallOptions{
		Options: Options{
			Root:      root,
			Runner:    runner.run,
			ResolveFn: func(string) ([]string, error) { return []string{"198.51.100.9"}, nil },
			// Deliberate mismatch: the A record points elsewhere.
			LocalAddrsFn: func() []string { return []string{"203.0.113.7"} },
		},
		preflight:    checks,
		BinarySource: source,
		Spec:         &spec,
		Output:       &out,
	})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil (the mismatch is a warning)", err)
	}
	if checkedDomain != domain {
		t.Errorf("preflight Options.Domain = %q, want %q", checkedDomain, domain)
	}
	text := out.String()
	if !strings.Contains(text, domain) || !strings.Contains(text, "запись домена должна указывать на этот сервер") {
		t.Errorf("output lacks the A/AAAA warning for %s:\n%s", domain, text)
	}
}

// TestRunFailsOnFailingCheck checks the gate itself and that warnings
// do not block the run.
func TestRunFailsOnFailingCheck(t *testing.T) {
	root, source, runner := installFixture(t)
	checks := func(Options) []Check {
		return []Check{
			{Name: "disk", Detail: "свободно 10 MiB на /, нужно не меньше 500 MiB"},
			{Name: "dns-a-record", Warning: true, Detail: "A/AAAA не совпадает"},
		}
	}
	spec := Spec{Domain: "dns.example.com"}

	var out bytes.Buffer
	err := Run(InstallOptions{
		Options:      Options{Root: root, Runner: runner.run},
		preflight:    checks,
		BinarySource: source,
		Spec:         &spec,
		Output:       &out,
	})
	if err == nil {
		t.Fatalf("Run() = nil, want the failing disk check to abort it")
	}
	if !strings.Contains(err.Error(), "disk: свободно 10 MiB") {
		t.Errorf("Run() error = %q, want it to name the disk check and its detail", err)
	}
	if !strings.Contains(out.String(), "A/AAAA не совпадает") {
		t.Errorf("Run() output does not print the warning:\n%s", out.String())
	}
	for _, p := range []string{"etc", "etc/mdns/config.json", "usr/local/bin/mdns", "var/lib/mdns"} {
		assertNotExist(t, filepath.Join(root, p))
	}
	if len(runner.calls) != 0 {
		t.Errorf("Run() ran commands %v, want none", runner.commands())
	}
}

// TestRooted pins the Root-relative path helper.
func TestRooted(t *testing.T) {
	tests := []struct {
		root, path string
		want       string
	}{
		{"/", "/etc/mdns/config.json", "/etc/mdns/config.json"},
		{"/tmp/root", "/etc/mdns/config.json", "/tmp/root/etc/mdns/config.json"},
		{"/tmp/root", "/tmp/root/etc/mdns/config.json", "/tmp/root/etc/mdns/config.json"},
		{"/tmp/root", "etc/mdns/config.json", "/tmp/root/etc/mdns/config.json"},
		{"/tmp/root", "/usr/local/bin/mdns", "/tmp/root/usr/local/bin/mdns"},
	}
	for _, tt := range tests {
		if got := rooted(tt.root, tt.path); got != tt.want {
			t.Errorf("rooted(%q, %q) = %q, want %q", tt.root, tt.path, got, tt.want)
		}
	}
}
