package diag

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"mydns/internal/api"
	"mydns/internal/cache"
	"mydns/internal/config"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/tlscert"
)

// shortTempDir returns a temporary directory with a short path: a unix
// socket path is limited to about a hundred bytes, which the long
// t.TempDir() names can exceed on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mdns-d")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// fakeDaemon serves the control API status over a unix socket, so the
// certificate check runs against a real Status call.
func fakeDaemon(t *testing.T, st api.Status) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on %s: %v", sock, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/status" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(st); err != nil {
			t.Errorf("encode status: %v", err)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})
	return sock
}

// writeConfig saves a config for the diagnostic to read and returns its
// path.
func writeConfig(t *testing.T, cfg *config.Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Save(path); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return path
}

// diagConfig is a minimal valid config: plain DNS only, on a free port,
// with the data directory in the temp tree.
func diagConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Domain = "dns.example.com"
	cfg.Protocols.DoH.Enabled = false
	cfg.Protocols.DoT.Enabled = false
	cfg.Protocols.DoQ.Enabled = false
	cfg.Protocols.Plain.Port = freePort(t)
	cfg.DataDir = t.TempDir()
	cfg.Log.File = ""
	return cfg
}

// freePort returns a port that can be bound right now.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen on a free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// busyPort returns a port held by a listener that stays open for the
// duration of the test.
func busyPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen on a busy port: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// okProbe is a Probe seam that answers every endpoint with a latency.
func okProbe(_ context.Context, eps []providers.Endpoint) []probe.Result {
	out := make([]probe.Result, 0, len(eps))
	for i, ep := range eps {
		out = append(out, probe.Result{Endpoint: ep, Latency: time.Duration(i+1) * time.Millisecond})
	}
	return out
}

// line returns the output line whose label matches, or "".
func line(out, label string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, label) {
			return l
		}
	}
	return ""
}

// TestStatusTextIncludesCertStates pins the human status lines: the
// summary carries the domain, the listeners, the strategy, the cache
// and the filter, and the certificate line names its state, the issuer
// or the error.
func TestStatusTextIncludesCertStates(t *testing.T) {
	tests := []struct {
		name string
		cert tlscert.Status
		want []string
	}{
		{
			name: "ok",
			cert: tlscert.Status{
				Mode:     "acme",
				State:    "ok",
				Issuer:   "Let's Encrypt",
				NotAfter: time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC),
			},
			want: []string{"Сертификат", "Let's Encrypt", "15.01.2027"},
		},
		{
			name: "waiting",
			cert: tlscert.Status{Mode: "acme", State: "waiting"},
			want: []string{"Сертификат", "ожидание"},
		},
		{
			name: "error",
			cert: tlscert.Status{Mode: "acme", State: "error", Error: "acme: no account"},
			want: []string{"Сертификат", "ошибка", "acme: no account"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := api.Status{
				Version:   "0.1.0",
				Domain:    "dns.example.com",
				Listeners: []string{"plain:53", "doh:443"},
				Strategy:  "fastest",
				Upstreams: []api.UpstreamStatus{
					{ID: "cloudflare", Name: "Cloudflare", Transport: "doh", Address: "https://cloudflare-dns.com/dns-query", Enabled: true, Healthy: true, LatencyMS: 12.3},
					{ID: "quad9", Name: "Quad9", Enabled: true, Failed: 2},
				},
				Cache:  cache.Stats{Hits: 10, Misses: 3, Size: 5},
				Filter: api.FilterSnapshot{Enabled: true, Mode: "zero", TotalBlocked: 4},
				Cert:   tt.cert,
			}

			text := StatusText(st)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Errorf("StatusText() does not contain %q:\n%s", want, text)
				}
			}
			for _, want := range []string{"dns.example.com", "plain:53", "doh:443", "fastest", "Cloudflare", "Кэш", "Фильтр"} {
				if !strings.Contains(text, want) {
					t.Errorf("StatusText() does not contain %q:\n%s", want, text)
				}
			}
		})
	}
}

// TestStatusReadsTheSocket checks the status client itself: it fetches
// /api/v1/status over the unix socket and decodes it.
func TestStatusReadsTheSocket(t *testing.T) {
	want := api.Status{Domain: "dns.example.com", Listeners: []string{"plain:53"}, Strategy: "fastest"}
	sock := fakeDaemon(t, want)

	got, err := Status(context.Background(), sock)
	if err != nil {
		t.Fatalf("Status() error = %v, want nil", err)
	}
	if got.Domain != want.Domain || got.Strategy != want.Strategy || len(got.Listeners) != 1 {
		t.Errorf("Status() = %+v, want %+v", got, want)
	}
}

// TestDiagFlagsIssues checks the exit code policy of diag: an invalid
// config is a failure (✗, exit 1), while a busy port and a dead daemon
// are warnings (!, exit 0).
func TestDiagFlagsIssues(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		var out bytes.Buffer
		code := Run(context.Background(), Options{
			ConfigPath: path,
			SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
			Out:        &out,
			Probe:      okProbe,
		})
		if code != 1 {
			t.Errorf("Run() = %d, want 1 for an invalid config", code)
		}
		if !strings.Contains(out.String(), "✗") {
			t.Errorf("output has no ✗ line:\n%s", out.String())
		}
		if l := line(out.String(), "Конфигурация"); !strings.Contains(l, "✗") || !strings.Contains(l, path) {
			t.Errorf("config line = %q, want a ✗ naming %s", l, path)
		}
	})

	t.Run("busy port", func(t *testing.T) {
		cfg := diagConfig(t)
		cfg.Protocols.Plain.Port = busyPort(t)
		path := writeConfig(t, cfg)

		var out bytes.Buffer
		code := Run(context.Background(), Options{
			ConfigPath: path,
			SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
			Out:        &out,
			Probe:      okProbe,
		})
		if code != 0 {
			t.Errorf("Run() = %d, want 0 for a busy port (a warning, not a failure)\n%s", code, out.String())
		}
		l := line(out.String(), "Порты")
		if !strings.HasPrefix(l, "!") {
			t.Errorf("ports line = %q, want a ! warning", l)
		}
		if !strings.Contains(l, itoa(cfg.Protocols.Plain.Port)) {
			t.Errorf("ports line = %q, want it to name the busy port", l)
		}
	})

	t.Run("daemon down is not a failure", func(t *testing.T) {
		cfg := diagConfig(t)
		path := writeConfig(t, cfg)

		var out bytes.Buffer
		code := Run(context.Background(), Options{
			ConfigPath: path,
			SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
			Out:        &out,
			Probe:      okProbe,
		})
		if code != 0 {
			t.Errorf("Run() = %d, want 0 when only the daemon is down\n%s", code, out.String())
		}
		if l := line(out.String(), "Сертификат"); !strings.HasPrefix(l, "!") {
			t.Errorf("certificate line = %q, want a ! warning with the daemon down", l)
		}
		if !strings.Contains(out.String(), "✓") {
			t.Errorf("output has no ✓ line:\n%s", out.String())
		}
	})

	t.Run("running daemon reports the certificate", func(t *testing.T) {
		cfg := diagConfig(t)
		path := writeConfig(t, cfg)
		sock := fakeDaemon(t, api.Status{
			Domain:   "dns.example.com",
			Strategy: "fastest",
			Cert: tlscert.Status{
				Mode:     "acme",
				State:    "ok",
				Issuer:   "Let's Encrypt",
				NotAfter: time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC),
			},
		})

		var out bytes.Buffer
		code := Run(context.Background(), Options{
			ConfigPath: path,
			SocketPath: sock,
			Out:        &out,
			Probe:      okProbe,
		})
		if code != 0 {
			t.Fatalf("Run() = %d, want 0\n%s", code, out.String())
		}
		l := line(out.String(), "Сертификат")
		if !strings.HasPrefix(l, "✓") || !strings.Contains(l, "Let's Encrypt") || !strings.Contains(l, "15.01.2027") {
			t.Errorf("certificate line = %q, want ✓ with the issuer and expiry", l)
		}
	})
}

// TestDiagProbeSeam checks the upstream check: the probe seam receives
// the config endpoints, a failure is a warning naming the upstream, and
// an all-ok run reports the best latency.
func TestDiagProbeSeam(t *testing.T) {
	cfg := diagConfig(t)
	cfg.Upstreams = []config.UpstreamConfig{
		{ID: "cloudflare", Name: "Cloudflare", Transport: "doh", Address: "https://cloudflare-dns.com/dns-query", Priority: 1, Enabled: true},
		{ID: "quad9", Name: "Quad9", Transport: "dot", Address: "9.9.9.9:853", ServerName: "dns.quad9.net", Priority: 2, Enabled: true},
		{ID: "off", Name: "Disabled", Transport: "plain", Address: "1.2.3.4:53", Priority: 3, Enabled: false},
	}
	path := writeConfig(t, cfg)

	var seen []providers.Endpoint
	failing := func(_ context.Context, eps []providers.Endpoint) []probe.Result {
		seen = eps
		out := make([]probe.Result, 0, len(eps))
		for i, ep := range eps {
			res := probe.Result{Endpoint: ep, Latency: time.Duration(5+i) * time.Millisecond}
			if ep.Transport == "dot" {
				res.Latency = 0
				res.Err = "timeout"
			}
			out = append(out, res)
		}
		return out
	}

	var out bytes.Buffer
	code := Run(context.Background(), Options{
		ConfigPath: path,
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		Out:        &out,
		Probe:      failing,
	})
	// Probe failures are warnings: they never change the exit code.
	if code != 0 {
		t.Errorf("Run() = %d, want 0 (probe failures are warnings)\n%s", code, out.String())
	}

	want := []providers.Endpoint{
		{Transport: "doh", Address: "https://cloudflare-dns.com/dns-query"},
		{Transport: "dot", Address: "9.9.9.9:853", ServerName: "dns.quad9.net"},
	}
	if len(seen) != len(want) {
		t.Fatalf("Probe() got %+v, want the two enabled upstreams %+v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("Probe() endpoint %d = %+v, want %+v", i, seen[i], want[i])
		}
	}

	l := line(out.String(), "Upstream'ы")
	if !strings.HasPrefix(l, "!") || !strings.Contains(l, "Quad9") || !strings.Contains(l, "timeout") {
		t.Errorf("upstream line = %q, want a ! naming Quad9 and its error", l)
	}

	// All endpoints healthy: a ✓ with the best latency.
	var ok bytes.Buffer
	if code := Run(context.Background(), Options{
		ConfigPath: path,
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		Out:        &ok,
		Probe:      okProbe,
	}); code != 0 {
		t.Fatalf("Run() = %d, want 0\n%s", code, ok.String())
	}
	l = line(ok.String(), "Upstream'ы")
	if !strings.HasPrefix(l, "✓") || !strings.Contains(l, "Cloudflare") || !strings.Contains(l, "1.0 ms") {
		t.Errorf("upstream line = %q, want ✓ with Cloudflare and the best latency", l)
	}
}

// TestDiagDataDirAndUnit checks the data directory and the unit file
// checks: a writable directory and a present unit are ✓, a missing
// directory and unit are !.
func TestDiagDataDirAndUnit(t *testing.T) {
	cfg := diagConfig(t)
	path := writeConfig(t, cfg)
	unitPath := filepath.Join(t.TempDir(), "mdns.service")
	if err := os.WriteFile(unitPath, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatalf("write unit: %v", err)
	}

	var out bytes.Buffer
	if code := Run(context.Background(), Options{
		ConfigPath: path,
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		UnitPath:   unitPath,
		Out:        &out,
		Probe:      okProbe,
	}); code != 0 {
		t.Fatalf("Run() = %d, want 0\n%s", code, out.String())
	}
	if l := line(out.String(), "Каталог данных"); !strings.HasPrefix(l, "✓") || !strings.Contains(l, cfg.DataDir) {
		t.Errorf("data dir line = %q, want ✓ naming %s", l, cfg.DataDir)
	}
	if l := line(out.String(), "Юнит"); !strings.HasPrefix(l, "✓") || !strings.Contains(l, unitPath) {
		t.Errorf("unit line = %q, want ✓ naming %s", l, unitPath)
	}
	entries, err := os.ReadDir(cfg.DataDir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the writability probe left %d entries in %s", len(entries), cfg.DataDir)
	}

	var miss bytes.Buffer
	if code := Run(context.Background(), Options{
		ConfigPath: path,
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		DataDir:    filepath.Join(t.TempDir(), "absent"),
		UnitPath:   filepath.Join(t.TempDir(), "absent.service"),
		Out:        &miss,
		Probe:      okProbe,
	}); code != 0 {
		t.Fatalf("Run() = %d, want 0 (missing paths are warnings)\n%s", code, miss.String())
	}
	for _, label := range []string{"Каталог данных", "Юнит"} {
		if l := line(miss.String(), label); !strings.HasPrefix(l, "!") {
			t.Errorf("%s line = %q, want a ! warning", label, l)
		}
	}
}

// TestDiagFilterLists checks the block-list cache: a list without
// persisted rules is a warning naming the list, and a cached list is ✓.
func TestDiagFilterLists(t *testing.T) {
	cfg := diagConfig(t)
	cfg.Filter.Enabled = true
	cfg.Filter.Lists = []config.FilterList{{ID: "hagezi"}, {ID: "easylist"}}
	path := writeConfig(t, cfg)

	var out bytes.Buffer
	if code := Run(context.Background(), Options{
		ConfigPath: path,
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		Out:        &out,
		Probe:      okProbe,
	}); code != 0 {
		t.Fatalf("Run() = %d, want 0\n%s", code, out.String())
	}
	if l := line(out.String(), "Списки фильтра"); !strings.HasPrefix(l, "!") || !strings.Contains(l, "hagezi") {
		t.Errorf("filter line = %q, want a ! naming the list without rules", l)
	}

	rulesDir := filepath.Join(cfg.DataDir, "filters")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("create filters dir: %v", err)
	}
	for _, id := range []string{"hagezi", "easylist"} {
		if err := os.WriteFile(filepath.Join(rulesDir, id+".rules"), []byte("+ads.example.com\n"), 0o644); err != nil {
			t.Fatalf("write rules: %v", err)
		}
	}

	var ok bytes.Buffer
	if code := Run(context.Background(), Options{
		ConfigPath: path,
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		Out:        &ok,
		Probe:      okProbe,
	}); code != 0 {
		t.Fatalf("Run() = %d, want 0\n%s", code, ok.String())
	}
	if l := line(ok.String(), "Списки фильтра"); !strings.HasPrefix(l, "✓") {
		t.Errorf("filter line = %q, want ✓ with both lists cached", l)
	}
}

// TestLogsUsesFileStreamWhenConfigured checks that a configured log file
// is tailed through the file seam, with the follow flag and N.
func TestLogsUsesFileStreamWhenConfigured(t *testing.T) {
	cfg := config.Default()
	cfg.Log.File = "/var/log/mdns/queries.jsonl"
	path := writeConfig(t, cfg)

	var (
		gotPath   string
		gotN      int
		gotFollow bool
		journal   bool
	)
	var out bytes.Buffer
	err := Logs(LogsOptions{
		ConfigPath: path,
		N:          7,
		Follow:     true,
		Out:        &out,
		FileStream: func(p string, n int, follow bool) (io.ReadCloser, error) {
			gotPath, gotN, gotFollow = p, n, follow
			return io.NopCloser(strings.NewReader("{\"q\":\"a.example.com\"}\n")), nil
		},
		JournalStream: func(int, bool) (io.ReadCloser, error) {
			journal = true
			return nil, errors.New("journalctl must not be used with log.file set")
		},
	})
	if err != nil {
		t.Fatalf("Logs() error = %v, want nil", err)
	}
	if journal {
		t.Error("Logs() used journalctl although log.file is set")
	}
	if gotPath != cfg.Log.File || gotN != 7 || !gotFollow {
		t.Errorf("FileStream(%q, %d, %v), want (%q, 7, true)", gotPath, gotN, gotFollow, cfg.Log.File)
	}
	if got := out.String(); got != "{\"q\":\"a.example.com\"}\n" {
		t.Errorf("output = %q, want the stream content", got)
	}
}

// TestLogsFallsBackToJournal checks the default source: without log.file
// the journal of the unit is streamed.
func TestLogsFallsBackToJournal(t *testing.T) {
	path := writeConfig(t, config.Default())

	var (
		gotN      int
		gotFollow bool
		file      bool
	)
	var out bytes.Buffer
	err := Logs(LogsOptions{
		ConfigPath: path,
		N:          42,
		Out:        &out,
		FileStream: func(string, int, bool) (io.ReadCloser, error) {
			file = true
			return nil, errors.New("tail must not be used without log.file")
		},
		JournalStream: func(n int, follow bool) (io.ReadCloser, error) {
			gotN, gotFollow = n, follow
			return io.NopCloser(strings.NewReader("журнал демона\n")), nil
		},
	})
	if err != nil {
		t.Fatalf("Logs() error = %v, want nil", err)
	}
	if file {
		t.Error("Logs() used the file stream although log.file is empty")
	}
	if gotN != 42 || gotFollow {
		t.Errorf("JournalStream(%d, %v), want (42, false)", gotN, gotFollow)
	}
	if got := out.String(); got != "журнал демона\n" {
		t.Errorf("output = %q, want the stream content", got)
	}
}

// TestLogsTail checks that N reaches the file seam and only the last N
// lines are copied out.
func TestLogsTail(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "mdns.log")
	content := "one\ntwo\nthree\nfour\nfive\n"
	if err := os.WriteFile(logFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	cfg := config.Default()
	cfg.Log.File = logFile
	path := writeConfig(t, cfg)

	var gotPath string
	var gotN int
	var gotFollow bool
	var out bytes.Buffer
	err := Logs(LogsOptions{
		ConfigPath: path,
		N:          2,
		Out:        &out,
		FileStream: func(p string, n int, follow bool) (io.ReadCloser, error) {
			gotPath, gotN, gotFollow = p, n, follow
			return io.NopCloser(strings.NewReader("four\nfive\n")), nil
		},
	})
	if err != nil {
		t.Fatalf("Logs() error = %v, want nil", err)
	}
	if gotPath != logFile || gotN != 2 || gotFollow {
		t.Errorf("FileStream(%q, %d, %v), want (%q, 2, false)", gotPath, gotN, gotFollow, logFile)
	}
	if got := out.String(); got != "four\nfive\n" {
		t.Errorf("output = %q, want the last two lines", got)
	}
}

// TestRealFileStream checks the real tail command on a file with five
// lines: it returns the last two.
func TestRealFileStream(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "mdns.log")
	if err := os.WriteFile(logFile, []byte("one\ntwo\nthree\nfour\nfive\n"), 0o600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	rc, err := fileStream(logFile, 2, false)
	if err != nil {
		t.Fatalf("fileStream() error = %v, want nil", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if string(got) != "four\nfive\n" {
		t.Errorf("fileStream() = %q, want the last two lines", got)
	}
}

// itoa is a small helper keeping the port assertions readable.
func itoa(n int) string {
	return strconv.Itoa(n)
}
