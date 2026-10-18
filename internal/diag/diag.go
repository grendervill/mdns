// Package diag implements the diagnostic CLI commands: `mdns diag`, a
// self-check of the installation and the running daemon, `mdns status`,
// the machine-readable state summary, and `mdns logs`, the log tail.
// Nothing in this package changes system state.
package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mydns/internal/api"
	"mydns/internal/config"
	"mydns/internal/installer"
	"mydns/internal/probe"
	"mydns/internal/providers"
	"mydns/internal/tlscert"
)

// Check marks of the diagnostic output. Only markFail changes the exit
// code: a missing certificate or a dead daemon is a warning, not a
// failed installation.
const (
	markOK   = "✓"
	markWarn = "!"
	markFail = "✗"
)

// DefaultSocketPath is where the daemon serves its control API.
const DefaultSocketPath = "/run/mdns/mdns.sock"

// statusTimeout bounds the status request over the socket.
const statusTimeout = 5 * time.Second

// Options is one diagnostic run. The zero value checks the default
// installation paths.
type Options struct {
	ConfigPath string // default /etc/mdns/config.json
	SocketPath string // default /run/mdns/mdns.sock
	DataDir    string // default: the config data_dir, else /var/lib/mdns
	UnitPath   string // default /etc/systemd/system/mdns.service
	Out        io.Writer
	// Probe measures upstream endpoints; nil uses probe.Measure. It is
	// the seam for tests, which cannot reach the public resolvers.
	Probe func(ctx context.Context, eps []providers.Endpoint) []probe.Result
}

// withDefaults fills the zero values of Options.
func (o Options) withDefaults() Options {
	if o.ConfigPath == "" {
		o.ConfigPath = installer.DefaultConfigPath
	}
	if o.SocketPath == "" {
		o.SocketPath = DefaultSocketPath
	}
	if o.UnitPath == "" {
		o.UnitPath = installer.UnitPath
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Probe == nil {
		o.Probe = func(ctx context.Context, eps []providers.Endpoint) []probe.Result {
			return probe.Measure(ctx, eps, probe.Options{})
		}
	}
	return o
}

// Run diagnoses the installation and returns the exit code: 1 when a
// check fails (✗), 0 when everything is fine or only warns (!). The
// checks cover the config, the listener ports, the certificate, the
// upstreams, the data directory, the cached filter lists and the
// systemd unit.
func Run(ctx context.Context, opts Options) int {
	o := opts.withDefaults()
	out := o.Out

	// The daemon state is fetched once: the port check uses it to tell a
	// running mdns from a foreign listener, and the certificate check
	// reads the certificate state from it.
	st, stErr := Status(ctx, o.SocketPath)

	failed := false
	report := func(mark, name, detail string) {
		fmt.Fprintf(out, "%s %s: %s\n", mark, name, detail)
		if mark == markFail {
			failed = true
		}
	}

	cfg := checkConfig(report, o.ConfigPath)

	if cfg != nil {
		checkPorts(report, cfg, stErr == nil)
	}
	checkCert(report, st, stErr)
	if cfg != nil {
		checkUpstreams(ctx, report, o.Probe, cfg)
	}

	dataDir := o.DataDir
	if dataDir == "" && cfg != nil {
		dataDir = cfg.DataDir
	}
	if dataDir == "" {
		dataDir = installer.DefaultDataDir
	}
	checkDataDir(report, dataDir)

	if cfg != nil {
		checkFilterLists(report, cfg, dataDir)
	}
	checkUnit(report, o.UnitPath)

	if failed {
		return 1
	}
	return 0
}

// checkConfig loads and validates the config, reporting the domain on
// success. A broken config is the one failure the other checks cannot
// work around, so it returns nil and the port, upstream and filter
// checks are skipped.
func checkConfig(report func(mark, name, detail string), configPath string) *config.Config {
	cfg, err := config.Load(configPath)
	if err != nil {
		report(markFail, "Конфигурация", fmt.Sprintf("%s — %v", configPath, err))
		return nil
	}
	if err := cfg.Validate(); err != nil {
		report(markFail, "Конфигурация", fmt.Sprintf("%s — %v", configPath, err))
		return nil
	}
	report(markOK, "Конфигурация", fmt.Sprintf("%s — домен %s", configPath, cfg.Domain))
	return cfg
}

// checkPorts tries to bind every port of the enabled protocols. A busy
// port is a warning: the daemon holding its own ports is the normal
// state of a healthy installation.
func checkPorts(report func(mark, name, detail string), cfg *config.Config, daemonUp bool) {
	ports := enabledPorts(cfg)
	if len(ports) == 0 {
		report(markOK, "Порты", "все протоколы выключены")
		return
	}

	var busy []string
	for _, port := range ports {
		if portBusy(port) {
			busy = append(busy, strconv.Itoa(port))
		}
	}
	if len(busy) == 0 {
		report(markOK, "Порты", fmt.Sprintf("свободны: %s", portList(ports)))
		return
	}

	note := "возможно, слушает другая служба"
	if daemonUp {
		note = "слушает запущенный mdns"
	}
	parts := make([]string, 0, len(busy))
	for _, port := range busy {
		parts = append(parts, fmt.Sprintf("%s (%s)", port, note))
	}
	report(markWarn, "Порты", fmt.Sprintf("заняты: %s", strings.Join(parts, ", ")))
}

// checkCert renders the certificate state reported by the daemon. A
// dead daemon is a warning: the certificate is only issued once the
// daemon runs, and the config may well be fine.
func checkCert(report func(mark, name, detail string), st api.Status, stErr error) {
	if stErr != nil {
		report(markWarn, "Сертификат", fmt.Sprintf("демон не запущен (%v)", stErr))
		return
	}
	report(certMark(st.Cert), "Сертификат", certDiagText(st.Cert))
}

// certMark maps a certificate state to the check mark: an issued
// certificate is fine, a pending one is a warning, a failed issuance is
// a failure, and a daemon that reports nothing is unknown.
func certMark(c tlscert.Status) string {
	switch c.State {
	case "ok":
		return markOK
	case "error":
		return markFail
	default:
		return markWarn
	}
}

// certDiagText describes a certificate state for the diagnostic output.
func certDiagText(c tlscert.Status) string {
	switch c.State {
	case "ok":
		parts := []string{"ok"}
		if c.Issuer != "" {
			parts = append(parts, c.Issuer)
		} else if c.Mode != "" {
			parts = append(parts, c.Mode)
		}
		if !c.NotAfter.IsZero() {
			parts = append(parts, "до "+c.NotAfter.Format(dateLayout))
		}
		return strings.Join(parts, ", ")
	case "waiting":
		return "ожидание выпуска"
	case "error":
		if c.Error != "" {
			return "ошибка — " + c.Error
		}
		return "ошибка"
	case "":
		return "демон не сообщил состояние сертификата"
	}
	return c.State
}

// checkUpstreams probes every enabled upstream. A failing upstream is a
// warning — routing has failover — and the best latency is reported
// when at least one answers.
func checkUpstreams(ctx context.Context, report func(mark, name, detail string), probeFn func(context.Context, []providers.Endpoint) []probe.Result, cfg *config.Config) {
	type upstream struct {
		name string
		ep   providers.Endpoint
	}

	var ups []upstream
	for _, u := range cfg.Upstreams {
		if !u.Enabled {
			continue
		}
		ups = append(ups, upstream{
			name: u.Name,
			ep:   providers.Endpoint{Transport: u.Transport, Address: u.Address, ServerName: u.ServerName},
		})
	}
	if len(ups) == 0 {
		report(markWarn, "Upstream'ы", "нет включённых upstream'ов")
		return
	}

	eps := make([]providers.Endpoint, 0, len(ups))
	for _, u := range ups {
		eps = append(eps, u.ep)
	}
	results := probeFn(ctx, eps)

	var best time.Duration
	var bestName string
	for i, u := range ups {
		if i >= len(results) {
			break
		}
		if err := results[i].Err; err != "" {
			report(markWarn, "Upstream'ы", fmt.Sprintf("%s (%s) — %s", upstreamName(u.name, u.ep), u.ep.Address, err))
			continue
		}
		if bestName == "" || results[i].Latency < best {
			best, bestName = results[i].Latency, upstreamName(u.name, u.ep)
		}
	}
	if bestName != "" {
		report(markOK, "Upstream'ы", fmt.Sprintf("лучший — %s, %s", bestName, latency(best)))
	}
}

// upstreamName falls back to the transport when an upstream has no
// name.
func upstreamName(name string, ep providers.Endpoint) string {
	if name != "" {
		return name
	}
	return ep.Transport
}

// checkDataDir verifies that the daemon's data directory exists and can
// be written: without it the cache, the lists and the certificates have
// nowhere to live. A missing directory is a warning (the daemon creates
// it), an unwritable one is a failure.
func checkDataDir(report func(mark, name, detail string), dataDir string) {
	info, err := os.Stat(dataDir)
	if err != nil {
		report(markWarn, "Каталог данных", fmt.Sprintf("%s отсутствует", dataDir))
		return
	}
	if !info.IsDir() {
		report(markFail, "Каталог данных", fmt.Sprintf("%s не каталог", dataDir))
		return
	}
	if err := probeWritable(dataDir); err != nil {
		report(markFail, "Каталог данных", fmt.Sprintf("%s недоступен для записи: %v", dataDir, err))
		return
	}
	report(markOK, "Каталог данных", dataDir+" доступен для записи")
}

// probeWritable creates and removes a temp file inside dir.
func probeWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".diag-*")
	if err != nil {
		return err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Remove(name)
}

// checkFilterLists verifies that the block lists have persisted rules
// under DataDir/filters. A list without rules is a warning: it is
// fetched on the first update after the daemon starts.
func checkFilterLists(report func(mark, name, detail string), cfg *config.Config, dataDir string) {
	if !cfg.Filter.Enabled {
		report(markOK, "Списки фильтра", "фильтрация выключена")
		return
	}
	if len(cfg.Filter.Lists) == 0 {
		report(markOK, "Списки фильтра", "фильтрация включена без списков")
		return
	}

	var missing []string
	for _, l := range cfg.Filter.Lists {
		if !safeListID(l.ID) {
			missing = append(missing, l.ID+" (недопустимый id)")
			continue
		}
		if _, err := os.Stat(filepath.Join(dataDir, "filters", l.ID+".rules")); err != nil {
			missing = append(missing, l.ID)
		}
	}
	if len(missing) == 0 {
		report(markOK, "Списки фильтра", fmt.Sprintf("правила на месте, списков %d", len(cfg.Filter.Lists)))
		return
	}
	report(markWarn, "Списки фильтра", fmt.Sprintf("%s — правила не загружены (будут скачаны при первом обновлении)", strings.Join(missing, ", ")))
}

// safeListID mirrors the filter engine's list-id rule: an id is a file
// name, so it must not escape the filters directory.
func safeListID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	return !strings.ContainsAny(id, `/\`) && !strings.Contains(id, "..")
}

// checkUnit verifies that the systemd unit is installed.
func checkUnit(report func(mark, name, detail string), unitPath string) {
	if _, err := os.Stat(unitPath); err != nil {
		report(markWarn, "Юнит", fmt.Sprintf("%s отсутствует (установите сервис: mdns install)", unitPath))
		return
	}
	report(markOK, "Юнит", unitPath)
}

// Status fetches the daemon status over the control API unix socket.
func Status(ctx context.Context, socketPath string) (api.Status, error) {
	var st api.Status

	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/api/v1/status", nil)
	if err != nil {
		return st, err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: statusTimeout}).Do(req)
	if err != nil {
		return st, fmt.Errorf("mdns API at %s: %w", socketPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("mdns API at %s: %s", socketPath, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return st, fmt.Errorf("mdns API at %s: decode status: %w", socketPath, err)
	}
	return st, nil
}

// StatusText renders the human summary of `mdns status`: the domain,
// the listeners, the routing strategy, the certificate, the upstreams,
// the cache and the filter.
func StatusText(st api.Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Домен: %s\n", valueOr(st.Domain, "(не задан)"))
	fmt.Fprintf(&b, "Порты: %s\n", valueOr(strings.Join(st.Listeners, ", "), "(нет)"))
	fmt.Fprintf(&b, "Стратегия: %s\n", valueOr(st.Strategy, "(не задана)"))
	fmt.Fprintf(&b, "Сертификат: %s\n", certStatusText(st.Cert))
	fmt.Fprintf(&b, "Upstream'ы: %s\n", upstreamsText(st.Upstreams))
	fmt.Fprintf(&b, "Кэш: попаданий %d, промахов %d, записей %d\n", st.Cache.Hits, st.Cache.Misses, st.Cache.Size)
	fmt.Fprintf(&b, "Фильтр: %s\n", filterText(st.Filter))
	return b.String()
}

// dateLayout is the Russian date format used by the interfaces.
const dateLayout = "02.01.2006"

// certStatusText describes the certificate for `mdns status`.
func certStatusText(c tlscert.Status) string {
	switch c.State {
	case "ok":
		parts := []string{"ok"}
		if c.Issuer != "" {
			parts = append(parts, c.Issuer)
		} else if c.Mode != "" {
			parts = append(parts, c.Mode)
		}
		if !c.NotAfter.IsZero() {
			parts = append(parts, "до "+c.NotAfter.Format(dateLayout))
		}
		return strings.Join(parts, ", ")
	case "waiting":
		return "ожидание выпуска"
	case "error":
		if c.Error != "" {
			return "ошибка — " + c.Error
		}
		return "ошибка"
	case "":
		return "нет данных"
	}
	return c.State
}

// upstreamsText summarises the upstream states on one line.
func upstreamsText(ups []api.UpstreamStatus) string {
	if len(ups) == 0 {
		return "нет"
	}
	parts := make([]string, 0, len(ups))
	for _, u := range ups {
		name := valueOr(u.Name, u.ID)
		switch {
		case !u.Enabled:
			parts = append(parts, name+" (выключен)")
		case u.Failed > 0 || !u.Healthy:
			parts = append(parts, fmt.Sprintf("%s (ошибок %d)", name, u.Failed))
		default:
			parts = append(parts, fmt.Sprintf("%s %.1f ms", name, u.LatencyMS))
		}
	}
	return strings.Join(parts, ", ")
}

// filterText summarises the block-list engine.
func filterText(f api.FilterSnapshot) string {
	if !f.Enabled {
		return "выключен"
	}
	return fmt.Sprintf("включён, режим %s, заблокировано %d, списков %d", f.Mode, f.TotalBlocked, len(f.Lists))
}

// enabledPorts lists the ports of the enabled protocols, without
// duplicates.
func enabledPorts(cfg *config.Config) []int {
	seen := map[int]bool{}
	var ports []int
	for _, p := range []config.Protocol{
		cfg.Protocols.Plain,
		cfg.Protocols.DoH,
		cfg.Protocols.DoT,
		cfg.Protocols.DoQ,
	} {
		if !p.Enabled || seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		ports = append(ports, p.Port)
	}
	return ports
}

// portBusy reports whether 0.0.0.0:port cannot be bound on TCP or UDP.
// The installer runs the same check before writing anything.
func portBusy(port int) bool {
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
	if l, err := net.Listen("tcp", addr); err == nil {
		l.Close()
	} else {
		return true
	}
	if c, err := net.ListenPacket("udp", addr); err == nil {
		c.Close()
	} else {
		return true
	}
	return false
}

// portList renders a port list for the human-readable detail.
func portList(ports []int) string {
	if len(ports) == 0 {
		return "(нет)"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ", ")
}

// latency renders a probe latency in milliseconds.
func latency(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
}

// valueOr returns s, or fallback when s is empty.
func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
