package metrics

import (
	_ "embed"
	"os"
	"path/filepath"
)

// ========================================================================
//  EMBEDDED DEFAULT ALLOWLIST
// ========================================================================
//
// The default allowlist.txt is compiled INTO the binary via go:embed.
// On first run, if the target file doesn't exist on disk, sysmon writes
// this default out to /etc/sysmon/allowlist.txt so the operator has an
// editable file — without needing to ship allowlist.txt separately.
//
// After that first write, sysmon always reads the on-disk file, so any
// edits the operator makes are preserved (we never overwrite an
// existing file).
//
// The embedded file lives at metrics/allowlist_default.txt — keep the
// canonical default there.

//go:embed allowlist_default.txt
var defaultAllowlistContent string

// EnsureAllowlistFile writes the embedded default to path if — and only
// if — no file already exists there.  Returns:
//   - created=true  if it wrote the default (first run)
//   - created=false if a file was already present (left untouched)
//   - err if the directory couldn't be created or the write failed
//
// It never overwrites an existing file, so operator edits are safe.
func EnsureAllowlistFile(path string) (created bool, err error) {
	if path == "" {
		path = "/etc/sysmon/allowlist.txt"
	}

	// Already exists → do nothing, preserve operator edits.
	if _, statErr := os.Stat(path); statErr == nil {
		return false, nil
	}

	// Create the parent directory (e.g. /etc/sysmon) if needed.
	dir := filepath.Dir(path)
	if mkErr := os.MkdirAll(dir, 0755); mkErr != nil {
		return false, mkErr
	}

	// Write the embedded default.
	if wErr := os.WriteFile(path, []byte(defaultAllowlistContent), 0644); wErr != nil {
		return false, wErr
	}

	return true, nil
}

// DefaultAllowlistContent returns the embedded default text (useful for
// a --dump-allowlist flag or diagnostics).
func DefaultAllowlistContent() string {
	return defaultAllowlistContent
}
