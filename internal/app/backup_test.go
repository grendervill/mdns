package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mydns/internal/configbackup"
)

// TestUpdateConfigSnapshotsOldConfig checks the automatic safety net: a
// persisted change stores the configuration it replaced, not the new one.
func TestUpdateConfigSnapshotsOldConfig(t *testing.T) {
	fake := newFakeUpstream(t)
	cfg := testConfig(t, fake, freePort(t))
	a, _ := startApp(t, cfg)

	infos, err := a.ListConfigBackups()
	if err != nil {
		t.Fatalf("ListConfigBackups() = %v, want nil", err)
	}
	if len(infos) != 0 {
		t.Fatalf("ListConfigBackups() = %+v, want none before the first change", infos)
	}

	next := *cfg
	next.Strategy = "failover"
	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}

	infos, err = a.ListConfigBackups()
	if err != nil {
		t.Fatalf("ListConfigBackups() = %v, want nil", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListConfigBackups() = %+v, want exactly the old config", infos)
	}
	old, err := configbackup.Load(filepath.Join(cfg.DataDir, "backups"), infos[0].Name)
	if err != nil {
		t.Fatalf("loading the automatic snapshot: %v", err)
	}
	if old.Strategy != cfg.Strategy {
		t.Errorf("snapshot strategy = %q, want the old %q", old.Strategy, cfg.Strategy)
	}
	if got := a.Config().Strategy; got != "failover" {
		t.Errorf("running strategy = %q, want failover", got)
	}
}

// TestRestoreConfigBackup checks that a restore applies the snapshot
// through UpdateConfig and snapshots the config it replaces first.
func TestRestoreConfigBackup(t *testing.T) {
	fake := newFakeUpstream(t)
	cfg := testConfig(t, fake, freePort(t))
	a, _ := startApp(t, cfg)

	if err := a.CreateConfigBackup("original"); err != nil {
		t.Fatalf("CreateConfigBackup() = %v, want nil", err)
	}
	infos, err := a.ListConfigBackups()
	if err != nil || len(infos) != 1 {
		t.Fatalf("ListConfigBackups() = %+v, %v, want one snapshot", infos, err)
	}
	original := infos[0].Name

	next := *cfg
	next.Strategy = "random"
	if err := a.UpdateConfig(context.Background(), &next); err != nil {
		t.Fatalf("UpdateConfig() = %v, want nil", err)
	}
	if got := a.Config().Strategy; got != "random" {
		t.Fatalf("running strategy = %q, want random", got)
	}

	if err := a.RestoreConfigBackup(original); err != nil {
		t.Fatalf("RestoreConfigBackup() = %v, want nil", err)
	}
	if got := a.Config().Strategy; got != cfg.Strategy {
		t.Errorf("restored strategy = %q, want %q", got, cfg.Strategy)
	}

	infos, err = a.ListConfigBackups()
	if err != nil {
		t.Fatalf("ListConfigBackups() after restore = %v, want nil", err)
	}
	preRestore := false
	for _, info := range infos {
		if !strings.Contains(info.Name, "-pre-restore") {
			continue
		}
		preRestore = true
		saved, err := configbackup.Load(filepath.Join(cfg.DataDir, "backups"), info.Name)
		if err != nil {
			t.Fatalf("loading the pre-restore snapshot: %v", err)
		}
		if saved.Strategy != "random" {
			t.Errorf("pre-restore snapshot strategy = %q, want the replaced random", saved.Strategy)
		}
	}
	if !preRestore {
		t.Errorf("restore did not snapshot the replaced config: %+v", infos)
	}
}

// TestRestoreConfigBackupInvalid checks Review Focus #3: a broken or
// incompatible snapshot is rejected before anything is applied or
// snapshotted.
func TestRestoreConfigBackupInvalid(t *testing.T) {
	fake := newFakeUpstream(t)
	cfg := testConfig(t, fake, freePort(t))
	a, _ := startApp(t, cfg)

	dir := filepath.Join(cfg.DataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "config-20260101-120000.json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"version": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	before := a.Config()
	infosBefore, err := a.ListConfigBackups()
	if err != nil {
		t.Fatalf("ListConfigBackups() = %v, want nil", err)
	}

	if err := a.RestoreConfigBackup(name); err == nil {
		t.Fatalf("RestoreConfigBackup(invalid) = nil, want an error")
	}

	after := a.Config()
	if after.Domain != before.Domain || after.Strategy != before.Strategy {
		t.Errorf("the running config changed: %+v, want %+v", after, before)
	}
	infosAfter, err := a.ListConfigBackups()
	if err != nil {
		t.Fatalf("ListConfigBackups() after the failed restore = %v, want nil", err)
	}
	if len(infosAfter) != len(infosBefore) {
		t.Errorf("the failed restore created a snapshot: %d files, want %d", len(infosAfter), len(infosBefore))
	}
}
