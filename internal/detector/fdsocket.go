// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// FDSocket flags two things:
//   - open file descriptors whose target path lies outside the baseline's
//     allow-listed prefixes (sandbox escape / sensitive-path access)
//   - established sockets to remote destinations not in the baseline's CIDR
//     allow-list (possible C2 / exfil)
//
// Remote-destination findings are MEDIUM (investigative) to avoid alert fatigue,
// per the plan. With no baseline, allow-lists are empty and only loopback/unroutable
// destinations are treated as benign.
type FDSocket struct{}

func (FDSocket) Name() string { return "fdsocket" }

func (FDSocket) Inspect(t *Target) ([]model.Finding, error) {
	var findings []model.Finding

	// --- file descriptors ---
	// Only enforce an fd policy when the baseline actually defines one. An absent
	// baseline OR an empty fd allow-list means "no fd policy" (don't judge), not
	// "deny all" — otherwise every legitimate fd would be flagged.
	var fdPrefixes []string
	if t.Baseline != nil {
		for _, r := range t.Baseline.FDs {
			fdPrefixes = append(fdPrefixes, r.PathPrefix)
		}
	}
	enforceFD := len(fdPrefixes) > 0
	for _, fd := range t.FDs {
		if !enforceFD {
			break
		}
		if !isRealPath(fd.Target) {
			continue // sockets, pipes, anon inodes handled via socket table
		}
		if allowedByPrefix(fd.Target, fdPrefixes) {
			continue
		}
		findings = append(findings, model.Finding{
			Technique: model.TechSensitiveFD,
			Severity:  model.SevMedium,
			PID:       t.Desc.PID,
			Title:     "file descriptor to path outside allow-list",
			Detail:    fmt.Sprintf("fd=%d -> %s", fd.Num, fd.Target),
			Evidence:  map[string]any{"fd": fd.Num, "target": fd.Target},
		})
	}

	// --- sockets ---
	// Only consider sockets the target actually owns: a socket fd renders as
	// "socket:[<inode>]", so build the set of inodes from the target's fds and
	// filter the (possibly namespace-wide) net table down to those. Without this,
	// a shared network namespace would surface every host connection.
	ownInodes := socketInodes(t.FDs)

	// As with fds, only enforce a destination policy when the baseline defines one;
	// without an allow-list, flagging every external connection is pure noise.
	var allowCIDRs []*net.IPNet
	if t.Baseline != nil {
		for _, r := range t.Baseline.Sockets {
			if _, ipnet, err := net.ParseCIDR(r.CIDR); err == nil {
				allowCIDRs = append(allowCIDRs, ipnet)
			}
		}
	}
	enforceSock := len(allowCIDRs) > 0
	for _, s := range t.Sockets {
		if !enforceSock {
			break
		}
		if _, owned := ownInodes[s.Inode]; !owned {
			continue // not this process's socket
		}
		if s.RemoteIP == nil || s.RemoteIP.IsUnspecified() {
			continue // listening / unconnected
		}
		if s.RemoteIP.IsLoopback() || s.RemoteIP.IsPrivate() || s.RemoteIP.IsLinkLocalUnicast() {
			continue // local traffic is not exfil
		}
		if ipInAny(s.RemoteIP, allowCIDRs) {
			continue
		}
		findings = append(findings, model.Finding{
			Technique: model.TechUnexpectedDest,
			Severity:  model.SevMedium,
			PID:       t.Desc.PID,
			Title:     "socket to destination outside allow-list",
			Detail:    fmt.Sprintf("%s %s:%d (%s)", s.Proto, s.RemoteIP, s.RemotePort, s.State),
			Evidence: map[string]any{
				"proto": s.Proto,
				"ip":    s.RemoteIP.String(),
				"port":  s.RemotePort,
				"state": s.State,
			},
		})
	}
	return findings, nil
}

func isRealPath(target string) bool {
	if target == "" {
		return false
	}
	// Non-file fds render as "socket:[...]", "pipe:[...]", "anon_inode:[...]".
	if strings.HasSuffix(target, "]") && strings.Contains(target, ":[") {
		return false
	}
	return strings.HasPrefix(target, "/")
}

func allowedByPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// socketInodes extracts the set of socket inodes from a process's fds. fd targets
// for sockets look like "socket:[12345]".
func socketInodes(fds []procfs.FD) map[uint64]struct{} {
	out := map[uint64]struct{}{}
	for _, fd := range fds {
		t := fd.Target
		if !strings.HasPrefix(t, "socket:[") || !strings.HasSuffix(t, "]") {
			continue
		}
		numStr := t[len("socket:[") : len(t)-1]
		if n, err := strconv.ParseUint(numStr, 10, 64); err == nil {
			out[n] = struct{}{}
		}
	}
	return out
}
