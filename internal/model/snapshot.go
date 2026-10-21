// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package model

import "time"

// TargetDesc identifies the process a snapshot or report refers to. It captures
// identity that is stable across runs (exe, build-id) separately from the
// run-specific pid, so a baseline taken from one run can be matched against a
// later run of the same program.
type TargetDesc struct {
	PID      int    `json:"pid"`
	Name     string `json:"name,omitempty"`     // selector used (e.g. "com.whatsapp")
	Exe      string `json:"exe,omitempty"`      // resolved /proc/<pid>/exe
	BuildID  string `json:"build_id,omitempty"` // GNU build-id of the main binary, if available
	Cmdline  string `json:"cmdline,omitempty"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	StartsAt int64  `json:"starts_at,omitempty"` // process start, unix seconds (bounds the window)
	// AppInstall is an Android app's install directory (procfs.AppInstall): a new
	// one per app update, so it tells the app's versions apart.
	AppInstall string `json:"app_install,omitempty"`
}

// Snapshot is a known-good baseline. It deliberately stores SHAPES and DIGESTS,
// never absolute addresses or raw memory — ASLR/PIE make virtual addresses
// meaningless across runs, and storing raw pages would blow the memory budget.
// A snapshot of a multi-GB process is only kilobytes.
type Snapshot struct {
	SchemaVersion int            `json:"schema_version"`
	ToolVersion   string         `json:"tool_version,omitempty"` // cenziadah build that created it
	CreatedAt     time.Time      `json:"created_at"`
	Target        TargetDesc     `json:"target"`
	Modules       []ModuleDigest `json:"modules"`
	Regions       []RegionShape  `json:"regions"`
	Children      []ChildRule    `json:"children,omitempty"`
	Sockets       []SocketRule   `json:"sockets,omitempty"`
	FDs           []FDRule       `json:"fds,omitempty"`
}

// CurrentSchemaVersion is bumped when the on-disk Snapshot format changes
// incompatibly, so load can refuse or migrate.
const CurrentSchemaVersion = 1

// ModuleDigest records the identity of a loaded, file-backed executable module so
// a later check can confirm it has not been tampered with in memory.
//
// Two digests are kept because an art/JIT-hosted process legitimately patches
// library .text in memory at load time (function-entry instrumentation), so live
// memory never equals the on-disk bytes. The check therefore compares live memory
// against MemTextSHA (the memory state captured from the KNOWN-GOOD process at
// snapshot time): identical => clean; different => a patch applied AFTER the
// baseline, i.e. a hook. DiskTextSHA + BuildID still anchor identity against the
// on-disk file (catching a swapped library).
type ModuleDigest struct {
	Path        string `json:"path"`
	BuildID     string `json:"build_id,omitempty"`
	DiskTextSHA string `json:"disk_text_sha256,omitempty"` // masked on-disk .text
	MemTextSHA  string `json:"mem_text_sha256,omitempty"`  // in-memory .text in the clean process
	TextSize    int64  `json:"text_size"`
}

// PermClass is the permission category of a memory region, used to key regions
// by shape rather than by address.
type PermClass string

const (
	PermRX  PermClass = "r-x" // normal code
	PermRWX PermClass = "rwx" // writable+executable (W^X violation unless whitelisted)
	PermRW  PermClass = "rw-"
	PermR   PermClass = "r--"
)

// RegionShape describes a memory mapping by its stable attributes (backing +
// permission class), not its runtime address. The baseline records which shapes
// are expected so a check can flag NEW anomalous shapes.
type RegionShape struct {
	Perm       PermClass `json:"perm"`
	Backing    string    `json:"backing,omitempty"` // file path, "[anon]", "memfd:...", or "(deleted)"
	Exec       bool      `json:"exec"`
	FileBacked bool      `json:"file_backed"`
}

// ChildRule allow-lists an expected child process by exe path.
type ChildRule struct {
	Exe     string `json:"exe"`
	BuildID string `json:"build_id,omitempty"`
}

// SocketRule allow-lists an expected remote destination.
type SocketRule struct {
	CIDR string `json:"cidr"`           // e.g. "157.240.0.0/16"
	Port int    `json:"port,omitempty"` // 0 = any
}

// FDRule allow-lists an expected open-file path prefix.
type FDRule struct {
	PathPrefix string `json:"path_prefix"`
}
