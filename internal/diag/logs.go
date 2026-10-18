package diag

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"

	"mydns/internal/config"
	"mydns/internal/installer"
)

const (
	// defaultLogLines is how many lines `mdns logs` shows without -n.
	defaultLogLines = 100
	// journalUnit is the systemd unit whose journal carries the daemon
	// log.
	journalUnit = "mdns"
)

// LogsOptions is one `mdns logs` run.
type LogsOptions struct {
	ConfigPath string // default /etc/mdns/config.json
	N          int    // lines to show; 0 → 100
	Follow     bool
	Out        io.Writer
	// JournalStream runs `journalctl -u mdns` (-n N, -f when Follow);
	// FileStream tails the given file (-n N, -f when Follow). Nil means
	// the real command; both are seams for the tests.
	JournalStream func(n int, follow bool) (io.ReadCloser, error)
	FileStream    func(path string, n int, follow bool) (io.ReadCloser, error)
}

// Logs streams the daemon log to Out: the file configured as log.file
// when there is one, the systemd journal of the unit otherwise. The
// stream is copied until it ends (without Follow) or the process is
// interrupted (with Follow).
func Logs(opts LogsOptions) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	configPath := opts.ConfigPath
	if configPath == "" {
		configPath = installer.DefaultConfigPath
	}
	n := opts.N
	if n <= 0 {
		n = defaultLogLines
	}

	journal := opts.JournalStream
	if journal == nil {
		journal = journalStream
	}
	file := opts.FileStream
	if file == nil {
		file = fileStream
	}

	stream, err := logStream(configPath, n, opts.Follow, file, journal)
	if err != nil {
		return err
	}
	defer stream.Close()

	if _, err := io.Copy(out, stream); err != nil {
		return err
	}
	return nil
}

// logStream picks the log source: the configured log file, or the
// journal. A config that does not exist yet is not an error — the
// daemon has not been set up here, so its journal is the best guess.
func logStream(
	configPath string,
	n int,
	follow bool,
	file func(path string, n int, follow bool) (io.ReadCloser, error),
	journal func(n int, follow bool) (io.ReadCloser, error),
) (io.ReadCloser, error) {
	cfg, err := config.Load(configPath)
	switch {
	case err == nil && cfg.Log.File != "":
		return file(cfg.Log.File, n, follow)
	case err == nil:
		return journal(n, follow)
	case errors.Is(err, os.ErrNotExist):
		return journal(n, follow)
	default:
		return nil, err
	}
}

// journalStream runs journalctl against the unit.
func journalStream(n int, follow bool) (io.ReadCloser, error) {
	args := []string{"-u", journalUnit, "-n", strconv.Itoa(n)}
	if follow {
		args = append(args, "-f")
	}
	return startStream("journalctl", args...)
}

// fileStream tails the log file through the system tail.
func fileStream(path string, n int, follow bool) (io.ReadCloser, error) {
	args := []string{"-n", strconv.Itoa(n)}
	if follow {
		args = append(args, "-f")
	}
	args = append(args, path)
	return startStream("tail", args...)
}

// startStream starts a command and returns its stdout as a stream whose
// Close reaps the process.
func startStream(name string, args ...string) (io.ReadCloser, error) {
	cmd := exec.Command(name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("запустить %s: %w", name, err)
	}
	return &cmdStream{stdout: stdout, cmd: cmd}, nil
}

// cmdStream is the stdout of a running command.
type cmdStream struct {
	stdout io.ReadCloser
	cmd    *exec.Cmd
}

// Read reads the command output.
func (c *cmdStream) Read(p []byte) (int, error) { return c.stdout.Read(p) }

// Close closes the pipe and waits for the command; a `tail -f` killed
// by the closed pipe is expected and not reported as an error.
func (c *cmdStream) Close() error {
	err := c.stdout.Close()
	if werr := c.cmd.Wait(); err == nil && werr != nil {
		return werr
	}
	return err
}
