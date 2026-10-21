// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package baseline builds, saves, and loads the known-good Snapshot that a check
// diffs against, and holds allow-list policy. A Snapshot stores shapes and digests
// only (never raw memory or absolute addresses), so it stays small and ASLR-proof.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/paulborile/cenziadah/internal/model"
)

// Save writes a Snapshot to path as indented JSON.
func Save(path string, s *model.Snapshot) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Load reads a Snapshot from path and checks its schema version.
func Load(path string) (*model.Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s model.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("baseline: parse %s: %w", path, err)
	}
	if s.SchemaVersion != model.CurrentSchemaVersion {
		return nil, fmt.Errorf("baseline: schema version %d, want %d", s.SchemaVersion, model.CurrentSchemaVersion)
	}
	return &s, nil
}
