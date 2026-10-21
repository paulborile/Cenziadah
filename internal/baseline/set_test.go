// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package baseline

import (
	"testing"

	"github.com/paulborile/cenziadah/internal/model"
)

func TestSetMergesSameIdentity(t *testing.T) {
	set := NewSet()
	set.Add("bash", &model.Snapshot{
		Regions:  []model.RegionShape{{Perm: model.PermRX, Backing: "/usr/bin/bash", Exec: true, FileBacked: true}},
		Children: []model.ChildRule{{Exe: "/usr/bin/ls"}},
		Modules:  []model.ModuleDigest{{Path: "/usr/lib/libc.so.6", BuildID: "b", MemTextSHA: "m1"}},
	})
	set.Add("bash", &model.Snapshot{
		Regions:  []model.RegionShape{{Perm: model.PermRX, Backing: "/usr/bin/bash", Exec: true, FileBacked: true}, {Perm: model.PermRWX, Backing: "[anon]", Exec: true}},
		Children: []model.ChildRule{{Exe: "/usr/bin/ls"}, {Exe: "/usr/bin/git"}},
		Modules:  []model.ModuleDigest{{Path: "/usr/lib/libc.so.6", BuildID: "b", MemTextSHA: "m1"}},
	})
	s := set.Lookup("bash")
	if set.Len() != 1 || s == nil {
		t.Fatalf("want one identity, got %v", set.Identities())
	}
	if len(s.Regions) != 2 || len(s.Children) != 2 || len(s.Modules) != 1 {
		t.Errorf("union wrong: %d regions, %d children, %d modules", len(s.Regions), len(s.Children), len(s.Modules))
	}
	if s.Modules[0].MemTextSHA != "m1" || set.Conflicts != 0 {
		t.Errorf("identical digests must merge cleanly: %+v conflicts=%d", s.Modules[0], set.Conflicts)
	}
}

// Two processes of one identity disagreeing on a module's known-good memory must
// not leave a digest that flags one of them: the module gets no memory opinion.
func TestSetDigestConflictDropsMemDigest(t *testing.T) {
	set := NewSet()
	set.Add("app", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/l.so", BuildID: "b", MemTextSHA: "m1"}}})
	set.Add("app", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/l.so", BuildID: "b", MemTextSHA: "m2"}}})
	if got := set.Lookup("app").Modules[0].MemTextSHA; got != "" || set.Conflicts != 1 {
		t.Errorf("MemTextSHA = %q conflicts = %d, want empty and 1", got, set.Conflicts)
	}
}

func TestSetLookupMissing(t *testing.T) {
	if NewSet().Lookup("nope") != nil {
		t.Error("missing identity must return nil")
	}
}

// A process without memory access contributes no digest; it must not erase the
// digest learned from a readable process of the same program.
func TestSetUnreadDigestIsNotAConflict(t *testing.T) {
	set := NewSet()
	set.Add("app", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/l.so", BuildID: "b"}}})
	set.Add("app", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/l.so", BuildID: "b", MemTextSHA: "m1"}}})
	set.Add("app", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/l.so", BuildID: "b"}}})
	if got := set.Lookup("app").Modules[0].MemTextSHA; got != "m1" || set.Conflicts != 0 {
		t.Errorf("MemTextSHA = %q conflicts = %d, want m1 and 0", got, set.Conflicts)
	}
}

// Once a module's digest is dropped for a conflict, a later process must not
// re-arm it with its own digest.
func TestSetConflictIsPermanent(t *testing.T) {
	set := NewSet()
	for _, d := range []string{"m1", "m2", "m3"} {
		set.Add("app", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/l.so", BuildID: "b", MemTextSHA: d}}})
	}
	if got := set.Lookup("app").Modules[0].MemTextSHA; got != "" || set.Conflicts != 1 {
		t.Errorf("MemTextSHA = %q conflicts = %d, want empty and 1", got, set.Conflicts)
	}
}

// After an upgrade the module's entry is replaced, not merged: a merge of two
// build-ids would drop the path's digest for good.
func TestReplaceModules(t *testing.T) {
	s := NewSet()
	s.Add("id", &model.Snapshot{Modules: []model.ModuleDigest{
		{Path: "/lib/a.so", BuildID: "old", MemTextSHA: "m1"},
		{Path: "/lib/b.so", BuildID: "b", MemTextSHA: "mb"},
	}})
	s.ReplaceModules("id", []model.ModuleDigest{{Path: "/lib/a.so", BuildID: "new", MemTextSHA: "m2"}})
	s.ReplaceModules("unknown", []model.ModuleDigest{{Path: "/lib/a.so", BuildID: "x"}}) // no-op
	got := s.Lookup("id").Modules
	if got[0].BuildID != "new" || got[0].MemTextSHA != "m2" || got[1].BuildID != "b" || got[1].MemTextSHA != "mb" {
		t.Errorf("modules = %+v", got)
	}
	// a later process of the same identity on the new version merges cleanly
	s.Add("id", &model.Snapshot{Modules: []model.ModuleDigest{{Path: "/lib/a.so", BuildID: "new", MemTextSHA: "m2"}}})
	if m := s.Lookup("id").Modules[0]; m.MemTextSHA != "m2" || s.Conflicts != 0 {
		t.Errorf("after merge: %+v conflicts=%d", m, s.Conflicts)
	}
}
