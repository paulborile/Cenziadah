// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"sync"

	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// TextCache reuses in-memory .text digests across processes and across sweeps,
// so N processes running the same binary or library are read once, not N times
// per sweep.
//
// Soundness: a digest is reused ONLY for a mapping whose smaps "Anonymous" size
// is known to be 0. A file-backed mapping with no anonymous pages has never been
// written in this process (any write, such as an inline hook, forces a
// copy-on-write private page), so its bytes are exactly the shared page cache of
// that file (dev+inode) and identical in every process mapping it. A patched
// process always has Anonymous > 0 on the patched mapping and is digested fresh,
// so the cache can never mask a hook. Keying on path or build-id alone would.
//
// Across sweeps: the page cache of a file changes only when the file does, and
// then its mtime and ctime change (ctime cannot be set back without root). The
// key therefore includes the module's Stamp (device, inode, size, mtime,
// ctime); a module without a Stamp is never cached. BeginSweep/EndSweep drop
// digests of files no sweep mapped any more.
type TextCache struct {
	mu     sync.Mutex
	m      map[textKey]textEntry
	gen    uint64 // current sweep
	hits   int
	misses int
}

type textEntry struct {
	sum string
	gen uint64 // last sweep that used it
}

type textKey struct {
	dev      string
	inode    uint64
	offset   uint64 // mapping file offset
	textOff  uint64
	textSize uint64
	buildID  string
	stamp    string // file version (elfref.Module.Stamp)
}

// NewTextCache returns an empty cache.
func NewTextCache() *TextCache {
	return &TextCache{m: make(map[textKey]textEntry)}
}

// BeginSweep starts a sweep: hit/miss counters restart.
func (c *TextCache) BeginSweep() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.hits, c.misses = 0, 0
}

// EndSweep drops the digests no process used during the sweep (files no longer
// mapped, or replaced), so the cache stays the size of what is running.
func (c *TextCache) EndSweep() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.m {
		if e.gen != c.gen {
			delete(c.m, k)
		}
	}
}

// Len is the number of cached digests.
func (c *TextCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// Stats returns how many digests were reused (hits) and computed (misses) for
// cache-eligible mappings.
func (c *TextCache) Stats() (hits, misses int) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

// Digest returns the masked in-memory .text digest, from the cache when the
// mapping is provably unwritten, otherwise by reading memory. A nil cache always
// reads memory.
func (c *TextCache) Digest(mem MemReader, r procfs.Region, mod *elfref.Module, buf []byte) (string, bool) {
	if c == nil || !cacheable(r) || mod.Stamp == "" {
		return MemTextDigest(mem, r, mod, buf)
	}
	k := textKey{dev: r.Dev, inode: r.Inode, offset: r.Offset,
		textOff: mod.TextOff, textSize: mod.TextSize, buildID: mod.BuildID, stamp: mod.Stamp}
	c.mu.Lock()
	e, ok := c.m[k]
	if ok {
		c.hits++
		e.gen = c.gen
		c.m[k] = e
	}
	c.mu.Unlock()
	if ok {
		return e.sum, true
	}
	sum, ok := MemTextDigest(mem, r, mod, buf)
	if !ok {
		return "", false // race/unreadable: nothing to cache
	}
	c.mu.Lock()
	c.m[k] = textEntry{sum: sum, gen: c.gen}
	c.misses++
	c.mu.Unlock()
	return sum, true
}

// cacheable reports whether r's bytes are guaranteed to equal the shared page
// cache of its backing file: smaps was read and shows no anonymous (CoW) pages,
// the mapping is not writable, and it has a real inode.
func cacheable(r procfs.Region) bool {
	return r.AnonKnown && r.AnonKB == 0 && !r.Write && r.Inode != 0 && r.Dev != ""
}
