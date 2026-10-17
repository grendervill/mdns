// Command mdns is the entrypoint of the mdns DNS server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mydns/internal/app"
	"mydns/internal/config"
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

	a, err := app.New(cfg, app.Options{SocketPath: *socketPath}, logger)
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
	m := tui.New(client, tui.Options{SocketPath: socketPath})
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mdns <command> [arguments]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  (без аргументов)  открыть панель управления (TUI)")
	fmt.Fprintln(os.Stderr, "  setup      мастер первичной настройки")
	fmt.Fprintln(os.Stderr, "  serve      run the mdns DNS server")
	fmt.Fprintln(os.Stderr, "  check      validate the configuration file")
	fmt.Fprintln(os.Stderr, "  tui        open the terminal interface")
	fmt.Fprintln(os.Stderr, "  version    print the mdns version")
}
