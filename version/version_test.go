package version

import (
	"testing"
)

func TestStringDefaults(t *testing.T) {
	want := "dev (commit: none, built: unknown)"
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringCustomValues(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	t.Cleanup(func() {
		Version, Commit, Date = origVersion, origCommit, origDate
	})

	Version = "v1.2.3"
	Commit = "abc1234"
	Date = "2026-01-01T00:00:00Z"

	want := "v1.2.3 (commit: abc1234, built: 2026-01-01T00:00:00Z)"
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
