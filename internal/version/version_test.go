package version_test

import (
	"testing"

	"mydns/internal/version"
)

func TestStringNotEmpty(t *testing.T) {
	if version.String() == "" {
		t.Fatal("empty version")
	}
}
