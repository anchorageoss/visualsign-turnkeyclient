package version

import (
	"testing"
)

func TestStringDefaults(t *testing.T) {
	want := "dev (commit: none)"
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestStringCustomValues(t *testing.T) {
	origVersion, origCommit := Version, Commit
	t.Cleanup(func() {
		Version, Commit = origVersion, origCommit
	})

	Version = "0.56.0+main-abc123def456"
	Commit = "abc123def456"

	want := "0.56.0+main-abc123def456 (commit: abc123def456)"
	if got := String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
