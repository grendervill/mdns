package installer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mydns/internal/config"
	"mydns/internal/links"
	"mydns/internal/setup"
	"mydns/internal/tui"
)

// Spec is the non-interactive setup: the values the wizard would ask
// for, ready to be turned into a config by buildConfig. Every field is
// optional except Domain.
type Spec struct {
	Domain        string
	TLSMode       string // acme | self-signed | files (default self-signed)
	ACMEProvider  string // letsencrypt | zerossl | custom (default letsencrypt)
	ACMEEmail     string
	ACMEDirectory string
	ACMEInsecure  bool
	EABKid        string
	EABHMAC       string
	CertFile      string
	KeyFile       string
	Providers     []string // catalog IDs; empty → ["cloudflare"]
	Strategy      string   // empty → fastest
	PlainPort     int      // 0 → 53
	DoHPort       int      // 0 → 443
	DoTPort       int      // 0 → 853
	DoQPort       int      // 0 → 853
	FilterPreset  string   // off | basic | strict (default off)
}

// InstallOptions is one installation run. It embeds the preflight
// Options, so Root, ConfigPath, DataDir, BindPorts and Runner are
// shared with the checks.
type InstallOptions struct {
	Options
	// BinarySource is the binary to install; empty uses the running
	// executable.
	BinarySource string
	// DryRun prints the plan and changes nothing.
	DryRun bool
	// Spec drives the non-interactive setup; nil runs the wizard.
	Spec *Spec
	// Reconfigure overwrites an existing config in the non-interactive
	// setup; without it an existing config is kept.
	Reconfigure bool
	// Output receives the progress and the summary; nil uses stdout.
	Output io.Writer

	// preflight is the check suite Run gates on; nil runs Preflight.
	// It is a seam for the tests: the real checks inspect the process
	// euid and the host system, which a temporary Root cannot satisfy.
	preflight func(Options) []Check
}

// plan describes the actions of one installation for the dry run.
type plan struct {
	dataDir      string
	configDir    string
	configPath   string
	configAction string
	binarySource string
	binaryPath   string
	unitPath     string
	ufwRules     []string
}

// Run installs mdns: preflight, directories, binary, config, systemd
// unit and firewall rules, then prints the summary. Everything happens
// under Options.Root and every system command goes through
// Options.Runner, so a caller without root can dry-run and the tests
// never touch the host.
func Run(opts InstallOptions) error {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}
	o := opts.Options.withDefaults()

	configPath := rooted(o.Root, o.ConfigPath)
	dataDir := rooted(o.Root, o.DataDir)
	binaryPath := rooted(o.Root, BinaryPath)
	unitPath := rooted(o.Root, UnitPath)

	// The non-interactive config is built and validated before anything
	// is written, so an invalid spec leaves the system untouched.
	var built *config.Config
	if opts.Spec != nil {
		cfg, err := buildConfig(*opts.Spec)
		if err != nil {
			return err
		}
		// The daemon reads its data (cache, the lists, the
		// certificates) from the directory the installer creates.
		cfg.DataDir = dataDir
		built = cfg
	}

	existing, err := loadExisting(configPath)
	if err != nil {
		return err
	}
	keep := existing != nil && opts.Spec != nil && !opts.Reconfigure

	// The config that will actually run decides the ports to check, the
	// firewall rules and the summary.
	effective := existing
	if built != nil && !keep {
		effective = built
	}
	if effective == nil {
		effective = config.Default()
	}
	if len(o.BindPorts) == 0 {
		o.BindPorts = enabledPorts(effective)
	}
	// The A/AAAA check needs the domain. A non-interactive run knows it
	// from the spec (or from the existing config it keeps); in the
	// interactive path the wizard has not asked for it yet, so the check
	// stays skipped there.
	if opts.Spec != nil && effective != nil {
		o.Domain = effective.Domain
	}

	// 1. Preflight: warnings are printed, failures abort.
	check := opts.preflight
	if check == nil {
		check = Preflight
	}
	var failed []string
	for _, c := range check(o) {
		switch {
		case c.Warning:
			fmt.Fprintf(out, "внимание: %s — %s\n", c.Name, c.Detail)
		case !c.OK:
			failed = append(failed, fmt.Sprintf("%s: %s", c.Name, c.Detail))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("проверки не пройдены:\n  %s", strings.Join(failed, "\n  "))
	}

	source := opts.BinarySource
	if source == "" {
		source, err = os.Executable()
		if err != nil {
			return fmt.Errorf("определить путь к устанавливаемому бинарнику: %w", err)
		}
	}

	// 2. Dry run: only the plan and the summary, nothing is written.
	if opts.DryRun {
		printPlan(out, plan{
			dataDir:      dataDir,
			configDir:    filepath.Dir(configPath),
			configPath:   configPath,
			configAction: configAction(built, keep),
			binarySource: source,
			binaryPath:   binaryPath,
			unitPath:     unitPath,
			ufwRules:     ufwRules(effective),
		})
		printSummary(out, effective, binaryPath, unitPath, true)
		return nil
	}

	// 3. Directories.
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("создать каталог %s: %w", filepath.Dir(configPath), err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("создать каталог %s: %w", dataDir, err)
	}
	fmt.Fprintf(out, "каталоги готовы: %s, %s\n", filepath.Dir(configPath), dataDir)

	// 4. Binary.
	if !sameFile(source, binaryPath) {
		if err := copyBinary(source, binaryPath); err != nil {
			return err
		}
		fmt.Fprintf(out, "бинарник установлен: %s\n", binaryPath)
	}

	// 5. Config: non-interactive from the spec, or the wizard.
	switch {
	case built != nil && keep:
		fmt.Fprintf(out, "конфиг уже существует, оставлен без изменений (--reconfigure для перезаписи): %s\n", configPath)
	case built != nil:
		if err := built.Save(configPath); err != nil {
			return err
		}
		fmt.Fprintf(out, "конфиг записан: %s\n", configPath)
	default:
		w, err := tui.NewWizard(setup.NewLocalBackend(configPath))
		if err != nil {
			return fmt.Errorf("мастер настройки: %w", err)
		}
		if err := w.Run(); err != nil {
			return fmt.Errorf("мастер настройки: %w", err)
		}
		if !w.Saved() {
			return errors.New("настройка отменена")
		}
		saved, err := config.Load(configPath)
		if err != nil {
			return fmt.Errorf("чтение сохранённого конфига: %w", err)
		}
		effective = saved
		fmt.Fprintf(out, "конфиг записан: %s\n", configPath)
	}

	// 6. Unit and service.
	unit := renderUnit(binaryPath, configPath)
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return fmt.Errorf("создать каталог %s: %w", filepath.Dir(unitPath), err)
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("записать юнит %s: %w", unitPath, err)
	}
	if err := os.Chmod(unitPath, 0o644); err != nil {
		return fmt.Errorf("chmod %s: %w", unitPath, err)
	}
	fmt.Fprintf(out, "юнит установлен: %s\n", unitPath)
	if _, err := o.Runner("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := o.Runner("systemctl", "enable", "--now", "mdns"); err != nil {
		return fmt.Errorf("systemctl enable --now mdns: %w", err)
	}

	// 7. Firewall.
	if err := applyUFW(out, o.Runner, ufwRules(effective)); err != nil {
		return err
	}

	// 8. Summary.
	printSummary(out, effective, binaryPath, unitPath, false)
	return nil
}

// rooted resolves a system path under root: the default paths of
// Options are already Root-relative, while explicit ones are absolute,
// so both forms land under root either way. With root "/" the paths are
// returned unchanged.
func rooted(root, p string) string {
	if p == "" {
		return p
	}
	clean := filepath.Clean(p)
	if root == "" || filepath.Clean(root) == string(filepath.Separator) {
		return clean
	}
	root = filepath.Clean(root)
	if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return clean
	}
	return filepath.Join(root, strings.TrimPrefix(clean, string(filepath.Separator)))
}

// loadExisting reads the config at path; a missing file is not an error
// and yields a nil config.
func loadExisting(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return cfg, nil
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

// configAction names what the config step will do, for the dry run.
func configAction(built *config.Config, keep bool) string {
	switch {
	case built != nil && keep:
		return "оставить существующий конфиг без изменений (--reconfigure для перезаписи)"
	case built != nil:
		return "записать новый конфиг"
	default:
		return "интерактивная настройка (мастер)"
	}
}

// sameFile reports whether the two paths are the same file.
func sameFile(a, b string) bool {
	if a == b {
		return true
	}
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

// copyBinary copies src over dst with mode 0755, creating the parent
// directories.
func copyBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("прочитать бинарник %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("создать каталог %s: %w", filepath.Dir(dst), err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("записать бинарник %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return fmt.Errorf("записать бинарник %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("закрыть бинарник %s: %w", dst, err)
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", dst, err)
	}
	return nil
}

// ufwRules is the set of ports the service needs, in the order they are
// opened: plain DNS, DoH (HTTP/3 uses UDP), the HTTP-01 challenge port
// when ACME cannot use TLS-ALPN-01 on 443, DoT and DoQ.
func ufwRules(cfg *config.Config) []string {
	seen := map[string]bool{}
	var rules []string
	add := func(rule string) {
		if seen[rule] {
			return
		}
		seen[rule] = true
		rules = append(rules, rule)
	}
	both := func(p config.Protocol) {
		if !p.Enabled {
			return
		}
		add(strconv.Itoa(p.Port) + "/tcp")
		add(strconv.Itoa(p.Port) + "/udp")
	}

	both(cfg.Protocols.Plain)
	both(cfg.Protocols.DoH)
	if cfg.TLS.Mode == "acme" && !(cfg.Protocols.DoH.Enabled && cfg.Protocols.DoH.Port == 443) {
		add("80/tcp")
	}
	if cfg.Protocols.DoT.Enabled {
		add(strconv.Itoa(cfg.Protocols.DoT.Port) + "/tcp")
	}
	if cfg.Protocols.DoQ.Enabled {
		add(strconv.Itoa(cfg.Protocols.DoQ.Port) + "/udp")
	}
	return rules
}

// applyUFW opens the ports when ufw is active; an inactive or missing
// ufw gets the manual instruction instead.
func applyUFW(out io.Writer, runner func(string, ...string) ([]byte, error), rules []string) error {
	status, err := runner("ufw", "status")
	if err != nil || !strings.Contains(string(status), "Status: active") {
		fmt.Fprintln(out, "ufw неактивен; откройте порты вручную:")
		for _, rule := range rules {
			fmt.Fprintf(out, "  sudo ufw allow %s\n", rule)
		}
		return nil
	}
	for _, rule := range rules {
		if _, err := runner("ufw", "allow", rule); err != nil {
			return fmt.Errorf("ufw allow %s: %w", rule, err)
		}
		fmt.Fprintf(out, "ufw: разрешён %s\n", rule)
	}
	return nil
}

// printPlan prints the planned installation of a dry run.
func printPlan(out io.Writer, p plan) {
	fmt.Fprintln(out, "План установки (DryRun):")
	fmt.Fprintf(out, "  создать каталог %s (0755)\n", p.configDir)
	fmt.Fprintf(out, "  создать каталог %s (0700)\n", p.dataDir)
	fmt.Fprintf(out, "  скопировать бинарник %s → %s (0755)\n", p.binarySource, p.binaryPath)
	fmt.Fprintf(out, "  конфигурация: %s → %s\n", p.configAction, p.configPath)
	fmt.Fprintf(out, "  записать юнит %s (0644)\n", p.unitPath)
	fmt.Fprintln(out, "  systemctl daemon-reload; systemctl enable --now mdns")
	if len(p.ufwRules) > 0 {
		fmt.Fprintf(out, "  ufw (если активен): allow %s\n", strings.Join(p.ufwRules, ", "))
	} else {
		fmt.Fprintln(out, "  ufw: правила не требуются")
	}
}

// printSummary prints the domain, the protocols with their device links,
// the upstreams, the strategy, the filter state and the installed paths.
func printSummary(out io.Writer, cfg *config.Config, binaryPath, unitPath string, dryRun bool) {
	fmt.Fprintln(out, "Итог:")
	fmt.Fprintf(out, "  Домен: %s\n", cfg.Domain)
	fmt.Fprintf(out, "  Сертификат: %s\n", cfg.TLS.Mode)
	if cfg.TLS.Mode == "acme" {
		fmt.Fprintln(out, "  Сертификат будет выпущен после запуска демона")
	}

	var protos []string
	for _, p := range []struct {
		name string
		on   bool
		port int
	}{
		{"plain", cfg.Protocols.Plain.Enabled, cfg.Protocols.Plain.Port},
		{"DoH", cfg.Protocols.DoH.Enabled, cfg.Protocols.DoH.Port},
		{"DoT", cfg.Protocols.DoT.Enabled, cfg.Protocols.DoT.Port},
		{"DoQ", cfg.Protocols.DoQ.Enabled, cfg.Protocols.DoQ.Port},
	} {
		if p.on {
			protos = append(protos, fmt.Sprintf("%s:%d", p.name, p.port))
		}
	}
	fmt.Fprintf(out, "  Протоколы: %s\n", strings.Join(protos, ", "))

	fmt.Fprintln(out, "  Ссылки для устройств:")
	for _, l := range links.Links(cfg) {
		fmt.Fprintf(out, "    %s — %s\n", l.Title, l.URI)
	}

	fmt.Fprintln(out, "  Провайдеры:")
	for _, u := range cfg.Upstreams {
		fmt.Fprintf(out, "    %s (%s) — %s\n", u.Name, u.Transport, u.Address)
	}

	fmt.Fprintf(out, "  Стратегия: %s\n", cfg.Strategy)
	if cfg.Filter.Enabled {
		fmt.Fprintf(out, "  Фильтрация: включена, списков %d\n", len(cfg.Filter.Lists))
	} else {
		fmt.Fprintln(out, "  Фильтрация: выключена")
	}

	if dryRun {
		fmt.Fprintf(out, "  Будет установлено (DryRun): бинарник %s, юнит %s\n", binaryPath, unitPath)
	} else {
		fmt.Fprintf(out, "  Установлено: бинарник %s, юнит %s\n", binaryPath, unitPath)
	}
}
