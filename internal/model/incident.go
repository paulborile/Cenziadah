// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package model

import "time"

// Endpoint is a remote socket endpoint observed for the target.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ChildProc records an observed child process of the target.
type ChildProc struct {
	PID     int    `json:"pid"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
}

// Triage holds cheap static-analysis results about a captured payload — enough
// to answer "is this code interesting?" without a full RE pass.
type Triage struct {
	Strings    []string `json:"strings,omitempty"`     // printable strings found in the blob
	Disasm     string   `json:"disasm,omitempty"`      // short disassembly of the entry bytes
	SyscallHit []string `json:"syscall_hit,omitempty"` // e.g. "execve","connect","socket"
	Class      string   `json:"class,omitempty"`       // heuristic: "reverse-shell","loader","dropper","unknown"
}

// Incident is a durable record of a confirmed compromise. It answers when, from/
// to where, and with what code. The payload blob is bounded and stored inert
// (never executed or loaded).
type Incident struct {
	ID            int64       `json:"id"`
	DetectedAt    time.Time   `json:"detected_at"`
	ProcStart     time.Time   `json:"proc_start"`
	PID           int         `json:"pid"`
	Exe           string      `json:"exe"`
	BuildID       string      `json:"build_id,omitempty"`
	Technique     Technique   `json:"technique"`
	Severity      Severity    `json:"severity"`
	PayloadSHA256 string      `json:"payload_sha256,omitempty"`
	PayloadSize   int         `json:"payload_size,omitempty"`
	PayloadBlob   []byte      `json:"payload_blob,omitempty"` // bounded; inert
	LiveRemoteIPs []Endpoint  `json:"live_remote_ips,omitempty"`
	RecentRemote  []Endpoint  `json:"recent_remote_ips,omitempty"`
	ChildProcs    []ChildProc `json:"child_procs,omitempty"`
	SuspiciousFDs []string    `json:"suspicious_fds,omitempty"`
	TriageInfo    *Triage     `json:"triage,omitempty"`
	RawReport     string      `json:"raw_report,omitempty"` // JSON of the triggering Report
}
