package installer

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// UninstallOptions is one uninstall run. It embeds the preflight
// Options, so Root, ConfigPath, DataDir and Runner are shared with the
// installation.
type UninstallOptions struct {
	Options
	// Purge also removes the configuration, the data directory and the
	// certificates; without it they are kept.
	Purge bool
	// KeepBinary leaves the installed binary in place.
	KeepBinary bool
	// Output receives the progress; nil uses stdout.
	Output io.Writer
}

// Uninstall removes the mdns installation: it stops and disables the
// service, deletes the systemd unit and (unless KeepBinary is set) the
// binary, then reloads systemd. By default the configuration, the data
// directory and the certificates are kept — a reinstall finds them
// again; Purge removes them too.
//
// Everything happens under Options.Root and every system command goes
// through Options.Runner, so the removal is testable without root. A
// missing path is not an error (a second uninstall is a no-op), while a
// path that cannot be removed is collected and reported after the
// remaining removals have run.
func Uninstall(opts UninstallOptions) error {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}
	o := opts.Options.withDefaults()

	unitPath := rooted(o.Root, UnitPath)
	binaryPath := rooted(o.Root, BinaryPath)
	configPath := rooted(o.Root, o.ConfigPath)
	dataDir := rooted(o.Root, o.DataDir)

	// The unit may never have been installed, or systemd may have
	// forgotten it: the service is stopped best effort, the files below
	// are what the uninstall is really about.
	if _, err := o.Runner("systemctl", "disable", "--now", "mdns"); err == nil {
		fmt.Fprintln(out, "служба остановлена и отключена: mdns")
	}

	var failed []string

	// remove deletes one path, reporting an unremovable path instead of
	// stopping: one stuck file must not keep the rest installed.
	remove := func(path string, recursive bool) {
		if _, err := os.Lstat(path); err != nil {
			fmt.Fprintf(out, "нет: %s\n", path)
			return
		}
		var err error
		if recursive {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
		switch {
		case err == nil:
			fmt.Fprintf(out, "удалено: %s\n", path)
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(out, "нет: %s\n", path)
		default:
			failed = append(failed, fmt.Sprintf("%s: %v", path, err))
			fmt.Fprintf(out, "не удалось удалить %s: %v\n", path, err)
		}
	}

	remove(unitPath, false)
	if _, err := o.Runner("systemctl", "daemon-reload"); err != nil {
		fmt.Fprintf(out, "systemctl daemon-reload: %v\n", err)
	}
	if opts.KeepBinary {
		fmt.Fprintf(out, "бинарник сохранён: %s\n", binaryPath)
	} else {
		remove(binaryPath, false)
	}

	if opts.Purge {
		remove(configPath, false)
		remove(dataDir, true)
	} else {
		fmt.Fprintf(out, "конфиг, данные и сертификаты сохранены: %s, %s\n", configPath, dataDir)
	}

	if len(failed) > 0 {
		return fmt.Errorf("не удалось удалить:\n  %s", strings.Join(failed, "\n  "))
	}
	return nil
}
