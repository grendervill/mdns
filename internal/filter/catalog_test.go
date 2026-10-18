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

// TestRegionalCatalog checks the regional block lists: at least 14
// entries, all https with hosts, and every ID unique across the whole
// catalog (the presets must not be disturbed by the addition).
func TestRegionalCatalog(t *testing.T) {
	entries := filter.Catalog()

	regional := 0
	regionalIDs := map[string]bool{}
	for _, e := range entries {
		if e.Category != "regional" {
			continue
		}
		regional++
		if regionalIDs[e.ID] {
			t.Errorf("regional id %q is duplicated", e.ID)
		}
		regionalIDs[e.ID] = true

		u, err := url.Parse(e.URL)
		if err != nil {
			t.Errorf("regional entry %q: url %q does not parse: %v", e.ID, e.URL, err)
			continue
		}
		if u.Scheme != "https" || u.Host == "" {
			t.Errorf("regional entry %q: url %q must be https with a host", e.ID, e.URL)
		}
	}
	if regional < 14 {
		t.Errorf("catalog has %d regional entries, want at least 14", regional)
	}

	for _, id := range []string{"ruadlist", "certpl-warning", "easylist-germany"} {
		if !regionalIDs[id] {
			t.Errorf("regional entry %q is missing", id)
		}
	}

	// Unique across the whole catalog, not just within the category.
	all := map[string]bool{}
	for _, e := range entries {
		if all[e.ID] {
			t.Errorf("catalog id %q is duplicated across categories", e.ID)
		}
		all[e.ID] = true
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
