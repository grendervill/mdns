// Command mdns is the entrypoint of the mdns DNS server.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mydns/internal/app"
	"mydns/internal/config"
	"mydns/internal/diag"
	"mydns/internal/installer"
	"mydns/internal/setup"
	"mydns/internal/tui"
	"mydns/internal/version"
)

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "version":
		fmt.Printf("mdns %s\n", version.String())
	case "serve":
		os.Exit(serveCmd(os.Args[2:]))
	case "check":
		os.Exit(checkCmd(os.Args[2:]))
	case "tui":
		os.Exit(tuiCmd(os.Args[2:]))
	case "setup":
		os.Exit(setupCmd(os.Args[2:]))
	case "install":
		os.Exit(installCmd(os.Args[2:]))
	case "uninstall":
		os.Exit(uninstallCmd(os.Args[2:]))
	case "status":
		os.Exit(statusCmd(os.Args[2:]))
	case "diag":
		os.Exit(diagCmd(os.Args[2:]))
	case "logs":
		os.Exit(logsCmd(os.Args[2:]))
	case "":
		os.Exit(tuiOrHint())
	default:
		usage()
		os.Exit(2)
	}
}

// serveCmd runs the DNS server until SIGINT or SIGTERM, then shuts it
// down within a five-second grace period.
func serveCmd(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/mdns/config.json", "path to the configuration file")
	socketPath := fs.String("socket", "", "control API socket path (default /run/mdns/mdns.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns serve:", err)
		return 1
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	a, err := app.New(cfg, serveOptions(*configPath, *socketPath), logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns serve:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := a.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "mdns serve:", err)
		return 1
	}
	logger.Info("mdns started", "domain", cfg.Domain)

	<-ctx.Done()
	logger.Info("mdns shutting down")

	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.Stop(sctx); err != nil {
		fmt.Fprintln(os.Stderr, "mdns serve:", err)
		return 1
	}
	return 0
}

// serveOptions assembles the app options for the serve command; the
// config path is what UpdateConfig persists to.
func serveOptions(configPath, socketPath string) app.Options {
	return app.Options{ConfigPath: configPath, SocketPath: socketPath}
}

// checkCmd validates the configuration and reports "ok".
func checkCmd(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/mdns/config.json", "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns check:", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "mdns check:", err)
		return 1
	}

	fmt.Println("ok")
	return 0
}

// tuiCmd runs the terminal interface against the daemon socket.
func tuiCmd(args []string) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	socketPath := fs.String("socket", "/run/mdns/mdns.sock", "path to the control API socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return tuiRun(*socketPath)
}

// tuiRun opens the TUI and returns its exit code.
func tuiRun(socketPath string) int {
	client := tui.NewUnixClient(socketPath)
	m := tui.New(client, tui.Options{})
	if err := m.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "mdns tui:", err)
		return 1
	}
	return 0
}

// tuiOrHint opens the TUI when the daemon answers and prints a hint
// otherwise (plain `mdns` with no arguments).
func tuiOrHint() int {
	socketPath := "/run/mdns/mdns.sock"

	conn, err := net.DialTimeout("unix", socketPath, 300*time.Millisecond)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Демон не запущен: сокет "+socketPath+" недоступен.")
		fmt.Fprintln(os.Stderr, "Первичная настройка: mdns setup")
		return 1
	}
	_ = conn.Close()
	return tuiRun(socketPath)
}

// setupCmd runs the first-run wizard against the local config file.
func setupCmd(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/mdns/config.json", "path to write the configuration to")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	backend := setup.NewLocalBackend(*configPath)
	w, err := tui.NewWizard(backend)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns setup:", err)
		return 1
	}
	if err := w.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "mdns setup:", err)
		return 1
	}

	if w.Saved() {
		fmt.Println(w.Summary())
		fmt.Println()
		fmt.Println("Дальше: systemctl start mdns — или, до установки сервиса:")
		fmt.Println("  mdns serve --config " + *configPath)
		return 0
	}
	fmt.Println("Настройка отменена; конфигурация не изменена.")
	return 1
}

// installFlags holds the parsed flags of the install command. The spec
// flags drive the non-interactive setup and are ignored without
// --non-interactive.
type installFlags struct {
	NonInteractive bool
	DryRun         bool
	Reconfigure    bool
	ConfigPath     string
	DataDir        string

	Domain        string
	TLSMode       string
	ACMEProvider  string
	ACMEEmail     string
	ACMEDirectory string
	ACMEInsecure  bool
	EABKid        string
	EABHMAC       string
	CertFile      string
	KeyFile       string
	Providers     []string
	Strategy      string
	PlainPort     int
	DoHPort       int
	DoTPort       int
	DoQPort       int
	FilterPreset  string
}

// installFlagSet registers the install flags on fs, filling f on Parse,
// and returns f.
func installFlagSet(fs *flag.FlagSet, f *installFlags) *installFlags {
	fs.BoolVar(&f.NonInteractive, "non-interactive", false, "install without the wizard, from the spec flags")
	fs.BoolVar(&f.DryRun, "dry-run", false, "print the plan and change nothing")
	fs.BoolVar(&f.Reconfigure, "reconfigure", false, "overwrite an existing config in the non-interactive setup")
	fs.StringVar(&f.ConfigPath, "config", installer.DefaultConfigPath, "path to the configuration file")
	fs.StringVar(&f.DataDir, "data-dir", installer.DefaultDataDir, "data directory (cache, lists, certificates)")

	fs.StringVar(&f.Domain, "domain", "", "service domain, e.g. dns.example.com")
	fs.StringVar(&f.TLSMode, "tls", "", "certificate source: acme, self-signed or files")
	fs.StringVar(&f.ACMEProvider, "acme-provider", "", "ACME CA: letsencrypt, zerossl or custom")
	fs.StringVar(&f.ACMEEmail, "acme-email", "", "ACME contact email")
	fs.StringVar(&f.ACMEDirectory, "acme-directory", "", "ACME directory URL of a custom CA")
	fs.BoolVar(&f.ACMEInsecure, "acme-insecure", false, "skip the ACME directory TLS verification")
	fs.StringVar(&f.EABKid, "eab-kid", "", "external account binding key id")
	fs.StringVar(&f.EABHMAC, "eab-hmac", "", "external account binding HMAC key")
	fs.StringVar(&f.CertFile, "cert-file", "", "certificate file for the files TLS mode")
	fs.StringVar(&f.KeyFile, "key-file", "", "private key file for the files TLS mode")
	fs.Var((*stringSlice)(&f.Providers), "provider", "upstream resolver id from the catalog (repeatable)")
	fs.StringVar(&f.Strategy, "strategy", "", "upstream strategy: fastest, failover, round_robin or random")
	fs.IntVar(&f.PlainPort, "plain-port", 0, "plain DNS port (default 53)")
	fs.IntVar(&f.DoHPort, "doh-port", 0, "DoH port (default 443)")
	fs.IntVar(&f.DoTPort, "dot-port", 0, "DoT port (default 853)")
	fs.IntVar(&f.DoQPort, "doq-port", 0, "DoQ port (default 853)")
	fs.StringVar(&f.FilterPreset, "filter", "", "filter preset: off, basic or strict")
	return f
}

// stringSlice collects a repeated string flag, e.g. --provider.
type stringSlice []string

// String implements flag.Value.
func (s *stringSlice) String() string { return strings.Join(*s, ",") }

// Set implements flag.Value.
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// installSpecFromFlags turns the install flags into the non-interactive
// Spec. Without --non-interactive the wizard asks for everything, so
// the spec flags are ignored and the Spec is nil.
func installSpecFromFlags(f installFlags) (*installer.Spec, error) {
	if !f.NonInteractive {
		return nil, nil
	}
	domain := strings.TrimSpace(f.Domain)
	if domain == "" {
		return nil, errors.New("--non-interactive требует --domain (домен сервиса)")
	}
	return &installer.Spec{
		Domain:        domain,
		TLSMode:       f.TLSMode,
		ACMEProvider:  f.ACMEProvider,
		ACMEEmail:     f.ACMEEmail,
		ACMEDirectory: f.ACMEDirectory,
		ACMEInsecure:  f.ACMEInsecure,
		EABKid:        f.EABKid,
		EABHMAC:       f.EABHMAC,
		CertFile:      f.CertFile,
		KeyFile:       f.KeyFile,
		Providers:     f.Providers,
		Strategy:      f.Strategy,
		PlainPort:     f.PlainPort,
		DoHPort:       f.DoHPort,
		DoTPort:       f.DoTPort,
		DoQPort:       f.DoQPort,
		FilterPreset:  f.FilterPreset,
	}, nil
}

// installCmd installs the service: the binary, the config, the systemd
// unit and the firewall rules. Without --non-interactive the wizard
// asks for the settings.
func installCmd(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var f installFlags
	installFlagSet(fs, &f)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	spec, err := installSpecFromFlags(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns install:", err)
		return 1
	}

	err = installer.Run(installer.InstallOptions{
		Options: installer.Options{
			Root:       "/",
			ConfigPath: f.ConfigPath,
			DataDir:    f.DataDir,
		},
		DryRun:      f.DryRun,
		Spec:        spec,
		Reconfigure: f.Reconfigure,
		Output:      os.Stdout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns install:", err)
		return 1
	}
	return 0
}

// uninstallCmd removes the service. It asks for confirmation on a
// terminal; --yes (or a pipe, or --non-interactive) skips the question.
func uninstallCmd(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "remove the config, the data and the certificates too")
	keepBinary := fs.Bool("keep-binary", false, "keep the installed binary")
	configPath := fs.String("config", installer.DefaultConfigPath, "path to the configuration file")
	dataDir := fs.String("data-dir", installer.DefaultDataDir, "data directory (cache, lists, certificates)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	// --non-interactive is the flag the installer documentation uses
	// for the same thing.
	nonInteractive := fs.Bool("non-interactive", false, "same as --yes")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if !*yes && !*nonInteractive && stdinIsTTY() {
		if *purge {
			fmt.Println("Будут удалены служба, бинарник, юнит, конфиг, данные и сертификаты.")
		} else {
			fmt.Println("Будут удалены служба, бинарник и юнит; конфиг, данные и сертификаты сохранятся.")
		}
		fmt.Print("Продолжить? [y/N] ")
		if !confirmUninstall(os.Stdin) {
			fmt.Println("отменено")
			return 1
		}
	}

	err := installer.Uninstall(installer.UninstallOptions{
		Options: installer.Options{
			Root:       "/",
			ConfigPath: *configPath,
			DataDir:    *dataDir,
		},
		Purge:      *purge,
		KeepBinary: *keepBinary,
		Output:     os.Stdout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns uninstall:", err)
		return 1
	}
	return 0
}

// stdinIsTTY reports whether stdin is a terminal, i.e. whether there is
// someone to answer the confirmation question.
func stdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// confirmUninstall reads one line and reports whether it is a yes.
func confirmUninstall(r io.Reader) bool {
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sc.Text())) {
	case "y", "yes", "д", "да":
		return true
	}
	return false
}

// statusCmd prints the daemon state, as text or as the API JSON.
func statusCmd(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socketPath := fs.String("socket", diag.DefaultSocketPath, "path to the control API socket")
	asJSON := fs.Bool("json", false, "print the raw status JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	st, err := diag.Status(ctx, *socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mdns status:", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(st); err != nil {
			fmt.Fprintln(os.Stderr, "mdns status:", err)
			return 1
		}
		return 0
	}

	fmt.Print(diag.StatusText(st))
	return 0
}

// diagCmd runs the installation self-check.
func diagCmd(args []string) int {
	fs := flag.NewFlagSet("diag", flag.ContinueOnError)
	configPath := fs.String("config", installer.DefaultConfigPath, "path to the configuration file")
	socketPath := fs.String("socket", diag.DefaultSocketPath, "path to the control API socket")
	dataDir := fs.String("data-dir", "", "data directory (default: the config data_dir)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return diag.Run(ctx, diag.Options{
		ConfigPath: *configPath,
		SocketPath: *socketPath,
		DataDir:    *dataDir,
		Out:        os.Stdout,
	})
}

// logsCmd prints the daemon log: the configured log file when there is
// one, the systemd journal otherwise.
func logsCmd(args []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	configPath := fs.String("config", installer.DefaultConfigPath, "path to the configuration file")
	n := fs.Int("n", 100, "how many lines to show")
	follow := fs.Bool("f", false, "follow the log")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := diag.Logs(diag.LogsOptions{
		ConfigPath: *configPath,
		N:          *n,
		Follow:     *follow,
		Out:        os.Stdout,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "mdns logs:", err)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mdns <command> [arguments]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  (без аргументов)  открыть панель управления (TUI)")
	fmt.Fprintln(os.Stderr, "  setup      мастер первичной настройки")
	fmt.Fprintln(os.Stderr, "  serve      run the mdns DNS server")
	fmt.Fprintln(os.Stderr, "  check      validate the configuration file")
	fmt.Fprintln(os.Stderr, "  tui        open the terminal interface")
	fmt.Fprintln(os.Stderr, "  install    установить сервис (бинарник, конфиг, systemd-юнит)")
	fmt.Fprintln(os.Stderr, "  uninstall  удалить сервис (--purge — вместе с конфигом и данными)")
	fmt.Fprintln(os.Stderr, "  status     состояние демона (--json — машинный вывод)")
	fmt.Fprintln(os.Stderr, "  diag       диагностика: конфиг, порты, сертификат, upstream'ы")
	fmt.Fprintln(os.Stderr, "  logs       журнал демона (-n N, -f)")
	fmt.Fprintln(os.Stderr, "  version    print the mdns version")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "mdns install --help, mdns uninstall --help: флаги установки")
}
