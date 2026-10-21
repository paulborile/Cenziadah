// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package baseline

import (
	"sort"
	"sync"

	"github.com/paulborile/cenziadah/internal/model"
)

// Set is the known-good state of a whole host: one Snapshot per process
// identity (see scan.Identity). Processes sharing an identity (ten bash shells,
// nginx workers) are merged into one Snapshot that accepts the union of their
// states. It satisfies scan.BaselineSource.
type Set struct {
	mu  sync.RWMutex
	ids map[string]*model.Snapshot
	// conflicted marks identity+module pairs whose memory digest was dropped, so
	// a later process cannot re-arm it with its own digest.
	conflicted map[string]bool
	// Conflicts counts modules whose known-good in-memory digest differed between
	// processes of one identity. Such a module keeps no memory digest (the check
	// gives no opinion on it) rather than flagging every process but one.
	Conflicts int
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{ids: make(map[string]*model.Snapshot), conflicted: make(map[string]bool)}
}

// Len returns the number of identities.
func (b *Set) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.ids)
}

// Lookup returns the Snapshot for an identity, or nil.
func (b *Set) Lookup(identity string) *model.Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ids[identity]
}

// Identities returns all identities, sorted.
func (b *Set) Identities() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.ids))
	for id := range b.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Add merges s into the Snapshot for identity. The Set takes ownership of s.
func (b *Set) Add(identity string, s *model.Snapshot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.ids[identity]
	if !ok {
		b.ids[identity] = s
		return
	}
	b.merge(identity, cur, s)
}

// merge folds src into dst (union of accepted state), counting module digest
// conflicts in b.Conflicts. Caller holds b.mu.
func (b *Set) merge(identity string, dst, src *model.Snapshot) {
	if src.CreatedAt.Before(dst.CreatedAt) {
		dst.CreatedAt = src.CreatedAt
	}

	haveRegion := map[model.RegionShape]bool{}
	for _, r := range dst.Regions {
		haveRegion[r] = true
	}
	for _, r := range src.Regions {
		if !haveRegion[r] {
			haveRegion[r] = true
			dst.Regions = append(dst.Regions, r)
		}
	}

	modIdx := map[string]int{}
	for i, m := range dst.Modules {
		modIdx[m.Path] = i
	}
	for _, m := range src.Modules {
		i, ok := modIdx[m.Path]
		if !ok {
			modIdx[m.Path] = len(dst.Modules)
			dst.Modules = append(dst.Modules, m)
			continue
		}
		b.mergeModule(identity, &dst.Modules[i], m)
	}

	haveChild := map[string]bool{}
	for _, c := range dst.Children {
		haveChild[c.Exe] = true
	}
	for _, c := range src.Children {
		if !haveChild[c.Exe] {
			haveChild[c.Exe] = true
			dst.Children = append(dst.Children, c)
		}
	}

	haveSock := map[model.SocketRule]bool{}
	for _, r := range dst.Sockets {
		haveSock[r] = true
	}
	for _, r := range src.Sockets {
		if !haveSock[r] {
			haveSock[r] = true
			dst.Sockets = append(dst.Sockets, r)
		}
	}

	haveFD := map[model.FDRule]bool{}
	for _, r := range dst.FDs {
		haveFD[r] = true
	}
	for _, r := range src.FDs {
		if !haveFD[r] {
			haveFD[r] = true
			dst.FDs = append(dst.FDs, r)
		}
	}
}

// mergeModule reconciles one module seen in two processes of an identity. An
// empty MemTextSHA means "not read" (no memory access), not a different state,
// so it never conflicts. Two different real digests, or two different build-ids,
// mean there is no single known-good state: the memory digest is dropped for
// good (the check gives no opinion) instead of flagging every process but one.
func (b *Set) mergeModule(identity string, d *model.ModuleDigest, m model.ModuleDigest) {
	k := identity + "\x00" + d.Path
	if b.conflicted[k] {
		return
	}
	switch {
	case d.BuildID != m.BuildID, d.MemTextSHA != "" && m.MemTextSHA != "" && d.MemTextSHA != m.MemTextSHA:
		b.conflicted[k] = true
		b.Conflicts++
		d.MemTextSHA = ""
	case d.MemTextSHA == "":
		d.MemTextSHA = m.MemTextSHA
	}
}

// ReplaceModules records mods as the known-good state of their paths for
// identity, REPLACING what was learned (a merge would see two build-ids and
// drop the path's digest for good). Used after a package upgrade replaced a
// library on disk (detector.EvidenceUpgraded); the old version is no longer
// what a new process of this program loads.
func (b *Set) ReplaceModules(identity string, mods []model.ModuleDigest) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.ids[identity]
	if !ok {
		return
	}
	for _, m := range mods {
		delete(b.conflicted, identity+"\x00"+m.Path)
		for i := range cur.Modules {
			if cur.Modules[i].Path == m.Path {
				cur.Modules[i] = m
			}
		}
	}
}
