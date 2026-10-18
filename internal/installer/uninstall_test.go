package installer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uninstallFixture builds a Root with a complete installation: the
// systemd unit, the binary, the config and a data directory with the
// certificates in it.
func uninstallFixture(t *testing.T) (root string, runner *fakeRunner) {
	t.Helper()
	root = t.TempDir()

	for _, p := range []string{
		"etc/systemd/system/mdns.service",
		"usr/local/bin/mdns",
		"etc/mdns/config.json",
		"var/lib/mdns/cache/.keep",
		"var/lib/mdns/certs/leaf.pem",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("create %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte("installed "+p), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}

	runner = newFakeRunner()
	runner.ok["systemctl"] = true
	return root, runner
}

// uninstallPaths are the fixture paths, relative to Root.
const (
	relUnit       = "etc/systemd/system/mdns.service"
	relBinary     = "usr/local/bin/mdns"
	relConfig     = "etc/mdns/config.json"
	relDataDir    = "var/lib/mdns"
	relCertFile   = "var/lib/mdns/certs/leaf.pem"
	relCacheEntry = "var/lib/mdns/cache/.keep"
)

// TestUninstallKeepsData checks the default uninstall: the service is
// stopped and disabled, the unit and the binary are gone, and the
// config, the data and the certificates stay in place.
func TestUninstallKeepsData(t *testing.T) {
	root, runner := uninstallFixture(t)

	var out bytes.Buffer
	err := Uninstall(UninstallOptions{
		Options: Options{Root: root, Runner: runner.run},
		Output:  &out,
	})
	if err != nil {
		t.Fatalf("Uninstall() error = %v, want nil", err)
	}

	assertNotExist(t, filepath.Join(root, relUnit))
	assertNotExist(t, filepath.Join(root, relBinary))

	for _, p := range []string{relConfig, relDataDir, relCertFile, relCacheEntry} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("%s is gone after a plain uninstall, want it kept: %v", p, err)
		}
	}

	want := []string{"systemctl disable --now mdns", "systemctl daemon-reload"}
	got := runner.commands()
	if len(got) != len(want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d = %q, want %q", i, got[i], want[i])
		}
	}

	text := out.String()
	for _, want := range []string{"удалено", filepath.Join(root, relUnit), "сохран", filepath.Join(root, relConfig)} {
		if !strings.Contains(text, want) {
			t.Errorf("output does not contain %q:\n%s", want, text)
		}
	}
}

// TestUninstallPurge checks --purge: the config, the data directory and
// the certificates go away with the service.
func TestUninstallPurge(t *testing.T) {
	root, runner := uninstallFixture(t)

	var out bytes.Buffer
	err := Uninstall(UninstallOptions{
		Options: Options{Root: root, Runner: runner.run},
		Purge:   true,
		Output:  &out,
	})
	if err != nil {
		t.Fatalf("Uninstall(--purge) error = %v, want nil", err)
	}

	for _, p := range []string{relUnit, relBinary, relConfig, relDataDir, relCertFile, relCacheEntry} {
		assertNotExist(t, filepath.Join(root, p))
	}
	if !strings.Contains(out.String(), filepath.Join(root, relDataDir)) {
		t.Errorf("purge output does not name the removed data dir:\n%s", out.String())
	}
}

// TestUninstallKeepBinary checks --keep-binary: the unit is removed and
// the binary stays.
func TestUninstallKeepBinary(t *testing.T) {
	root, runner := uninstallFixture(t)

	var out bytes.Buffer
	err := Uninstall(UninstallOptions{
		Options:    Options{Root: root, Runner: runner.run},
		KeepBinary: true,
		Output:     &out,
	})
	if err != nil {
		t.Fatalf("Uninstall(--keep-binary) error = %v, want nil", err)
	}

	assertNotExist(t, filepath.Join(root, relUnit))
	if _, err := os.Stat(filepath.Join(root, relBinary)); err != nil {
		t.Errorf("binary is gone with --keep-binary, want it kept: %v", err)
	}
	if !strings.Contains(out.String(), filepath.Join(root, relBinary)) {
		t.Errorf("output does not mention the kept binary:\n%s", out.String())
	}
}

// TestUninstallContinuesOnPathErrors checks that a path that cannot be
// removed is reported and does not stop the remaining removals: the
// error names the failing path while everything else is gone.
func TestUninstallContinuesOnPathErrors(t *testing.T) {
	root, runner := uninstallFixture(t)

	// A non-empty directory where the binary is expected: os.Remove
	// cannot delete it, while every other path stays removable.
	binaryPath := filepath.Join(root, relBinary)
	if err := os.Remove(binaryPath); err != nil {
		t.Fatalf("remove fixture binary: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(binaryPath, "junk"), 0o755); err != nil {
		t.Fatalf("create unremovable binary dir: %v", err)
	}

	var out bytes.Buffer
	err := Uninstall(UninstallOptions{
		Options: Options{Root: root, Runner: runner.run},
		Purge:   true,
		Output:  &out,
	})
	if err == nil {
		t.Fatalf("Uninstall() = nil, want an error naming the unremovable binary")
	}
	if !strings.Contains(err.Error(), binaryPath) {
		t.Errorf("Uninstall() error = %q, want it to name %s", err, binaryPath)
	}

	assertNotExist(t, filepath.Join(root, relUnit))
	assertNotExist(t, filepath.Join(root, relConfig))
	assertNotExist(t, filepath.Join(root, relDataDir))
	if !strings.Contains(out.String(), "не удалось удалить") {
		t.Errorf("output does not report the failed removal:\n%s", out.String())
	}
}

// TestUninstallMissingPaths checks idempotence: uninstalling a system
// that holds nothing but a stopped service is not an error.
func TestUninstallMissingPaths(t *testing.T) {
	root := t.TempDir()
	runner := newFakeRunner()
	runner.ok["systemctl"] = true

	var out bytes.Buffer
	if err := Uninstall(UninstallOptions{
		Options: Options{Root: root, Runner: runner.run},
		Purge:   true,
		Output:  &out,
	}); err != nil {
		t.Fatalf("Uninstall() on an empty Root = %v, want nil", err)
	}
	if !strings.Contains(out.String(), "нет") {
		t.Errorf("output does not mention the missing paths:\n%s", out.String())
	}
}

// TestUninstallIgnoresSystemctlErrors checks that a systemctl that
// cannot stop the unit (the unit may not be loaded) does not abort the
// removal of the files.
func TestUninstallIgnoresSystemctlErrors(t *testing.T) {
	root, _ := uninstallFixture(t)
	failing := func(string, ...string) ([]byte, error) {
		return []byte("Unit mdns.service not loaded."), errors.New("exit status 5")
	}

	var out bytes.Buffer
	if err := Uninstall(UninstallOptions{
		Options: Options{Root: root, Runner: failing},
		Output:  &out,
	}); err != nil {
		t.Fatalf("Uninstall() with a failing systemctl = %v, want nil", err)
	}
	assertNotExist(t, filepath.Join(root, relUnit))
}
