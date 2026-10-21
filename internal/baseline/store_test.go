// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package baseline

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/paulborile/cenziadah/internal/model"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	s := &model.Snapshot{
		SchemaVersion: model.CurrentSchemaVersion,
		CreatedAt:     time.Now().Truncate(time.Second),
		Target:        model.TargetDesc{PID: 5, Name: "demo", Exe: "/usr/bin/demo"},
		Modules:       []model.ModuleDigest{{Path: "/lib/x.so", BuildID: "abc", DiskTextSHA: "deadbeef", TextSize: 10}},
		Regions:       []model.RegionShape{{Perm: "r-x", Backing: "/usr/bin/demo", Exec: true, FileBacked: true}},
	}
	path := filepath.Join(t.TempDir(), "base.json")
	if err := Save(path, s); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Target.Name != "demo" || len(got.Modules) != 1 || got.Modules[0].DiskTextSHA != "deadbeef" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestLoadRejectsBadSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	Save(path, &model.Snapshot{SchemaVersion: 999})
	if _, err := Load(path); err == nil {
		t.Error("expected schema-version error")
	}
}
