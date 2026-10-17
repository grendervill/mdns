package filter_test

import (
	"net/url"
	"testing"

	"mydns/internal/filter"
)

// TestCatalogShape checks the built-in catalog: filled entries, https
// URLs with hosts, and unique IDs.
func TestCatalogShape(t *testing.T) {
	entries := filter.Catalog()
	if len(entries) < 10 {
		t.Fatalf("catalog has %d entries, want at least 10", len(entries))
	}

	seen := map[string]bool{}
	for _, e := range entries {
		if e.ID == "" || e.Name == "" || e.URL == "" || e.Category == "" || e.Description == "" {
			t.Errorf("catalog entry %+v has empty fields", e)
		}
		if seen[e.ID] {
			t.Errorf("catalog id %q is duplicated", e.ID)
		}
		seen[e.ID] = true

		u, err := url.Parse(e.URL)
		if err != nil {
			t.Errorf("entry %q: url %q does not parse: %v", e.ID, e.URL, err)
			continue
		}
		if u.Scheme != "https" || u.Host == "" {
			t.Errorf("entry %q: url %q must be https with a host", e.ID, e.URL)
		}
	}
}

// TestPresetRefsExist checks that presets only reference catalog IDs.
func TestPresetRefsExist(t *testing.T) {
	for _, name := range []string{"basic", "strict"} {
		ids, ok := filter.Preset(name)
		if !ok || len(ids) == 0 {
			t.Fatalf("Preset(%q) = (%v, %v), want a non-empty set", name, ids, ok)
		}
		for _, id := range ids {
			if _, ok := filter.EntryByID(id); !ok {
				t.Errorf("preset %q references unknown catalog id %q", name, id)
			}
		}
	}

	if _, ok := filter.Preset("bogus"); ok {
		t.Errorf("Preset(bogus) = ok, want false")
	}
}
