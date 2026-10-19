// Package configbackup stores timestamped snapshots of the server
// configuration under a directory, loads them back through the same
// migration path the daemon uses for its own config file, and prunes
// old snapshots so the directory stays bounded. Snapshots are plain
// JSON in the daemon's exact on-disk format: a backup can be copied
// over the config file by hand.
package configbackup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mydns/internal/config"
)

// retain is how many snapshots Create keeps; the oldest beyond it are
// pruned. Ten covers a rollback chain without letting an unattended
// panel's saves fill the data directory.
const retain = 10

// namePrefix and nameSuffix are the shape of a snapshot file:
// config-20060102-150405[-label].json.
const (
	namePrefix = "config-"
	nameSuffix = ".json"
	timeLayout = "20060102-150405"
)

// Info describes one stored snapshot.
type Info struct {
	Name    string
	Size    int64
	ModTime time.Time
}

// Create marshals cfg exactly as the daemon persists it and writes it
// atomically to dir as config-20060102-150405[-label].json. The
// directory is created with mode 0700 and the file with 0600; the
// oldest snapshots beyond ten are deleted afterwards. An empty or
// fully sanitized-away label simply leaves the label off the name.
func Create(dir string, cfg *config.Config, label string) (Info, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Info{}, fmt.Errorf("configbackup: create directory %s: %w", dir, err)
	}

	base := namePrefix + time.Now().Format(timeLayout)
	if label = sanitizeLabel(label); label != "" {
		base += "-" + label
	}

	name := base + nameSuffix
	for i := 2; ; i++ {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			break
		}
		// Two snapshots in the same second would otherwise overwrite
		// each other; the counter keeps both and the name pattern.
		name = fmt.Sprintf("%s-%d%s", base, i, nameSuffix)
	}

	path := filepath.Join(dir, name)
	// Save writes the JSON with the daemon's indent, fsyncs a temp file
	// and renames it into place, so a snapshot is never half-written.
	if err := cfg.Save(path); err != nil {
		return Info{}, fmt.Errorf("configbackup: write %s: %w", path, err)
	}

	info, err := stat(path)
	if err != nil {
		return Info{}, err
	}
	if err := prune(dir); err != nil {
		return info, err
	}
	return info, nil
}

// List returns the stored snapshots, newest first. A missing directory
// means no snapshots yet and is not an error.
func List(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("configbackup: read directory %s: %w", dir, err)
	}

	out := make([]Info, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, namePrefix) || !strings.HasSuffix(name, nameSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("configbackup: stat %s: %w", filepath.Join(dir, name), err)
		}
		out = append(out, Info{Name: name, Size: info.Size(), ModTime: info.ModTime()})
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].Name > out[j].Name
	})
	return out, nil
}

// Load reads one snapshot through config.Load — the daemon's own read
// and migration path — and then validates it, exactly as the daemon
// validates a config before applying it. name must be a base name in
// dir with the .json suffix.
func Load(dir, name string) (*config.Config, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	cfg, err := config.Load(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("configbackup: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configbackup: %s: %w", name, err)
	}
	return cfg, nil
}

// Delete removes one snapshot. name must be a base name in dir with the
// .json suffix.
func Delete(dir, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("configbackup: delete %s: %w", name, err)
	}
	return nil
}

// prune deletes the oldest snapshots beyond retain. It is best-effort
// per file: a file that disappears between the listing and the removal
// is not an error.
func prune(dir string) error {
	infos, err := List(dir)
	if err != nil {
		return err
	}
	if len(infos) <= retain {
		return nil
	}
	for _, info := range infos[retain:] {
		if err := os.Remove(filepath.Join(dir, info.Name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("configbackup: prune %s: %w", info.Name, err)
		}
	}
	return nil
}

// stat builds the Info of a snapshot.
func stat(path string) (Info, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Info{}, fmt.Errorf("configbackup: stat %s: %w", path, err)
	}
	return Info{Name: filepath.Base(path), Size: info.Size(), ModTime: info.ModTime()}, nil
}

// validateName accepts only a plain file name with the .json suffix, so
// a request can never address a file outside dir.
func validateName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("configbackup: invalid backup name %q", name)
	}
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return fmt.Errorf("configbackup: invalid backup name %q", name)
	}
	if !strings.HasSuffix(name, nameSuffix) || name == nameSuffix {
		return fmt.Errorf("configbackup: invalid backup name %q (want a .json file)", name)
	}
	return nil
}

// sanitizeLabel turns an arbitrary label into the [a-z0-9-]{1,32} slug
// the file name carries: lowercase ASCII only, runs of anything else
// collapse to one dash, no leading or trailing dash, at most 32 bytes.
func sanitizeLabel(label string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(label) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			if pendingDash && b.Len() > 0 && b.Len() < 32 {
				b.WriteByte('-')
			}
			pendingDash = false
			if b.Len() < 32 {
				b.WriteRune(r)
			}
		default:
			pendingDash = true
		}
	}
	return b.String()
}
