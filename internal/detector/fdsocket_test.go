// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"net"
	"testing"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

func TestFDSocketUnexpectedDest(t *testing.T) {
	base := &model.Snapshot{
		Sockets: []model.SocketRule{{CIDR: "157.240.0.0/16"}}, // Meta-ish allow-list
	}
	target := &Target{
		Desc:     model.TargetDesc{PID: 200},
		Baseline: base,
		FDs: []procfs.FD{
			{Num: 10, Target: "socket:[1001]"},
			{Num: 11, Target: "socket:[1002]"},
			{Num: 12, Target: "socket:[1003]"},
		},
		Sockets: []procfs.Socket{
			{Proto: "tcp", Inode: 1001, RemoteIP: net.ParseIP("157.240.1.1"), RemotePort: 443, State: "ESTABLISHED"},  // allowed
			{Proto: "tcp", Inode: 1002, RemoteIP: net.ParseIP("203.0.113.9"), RemotePort: 4444, State: "ESTABLISHED"}, // C2 (owned)
			{Proto: "tcp", Inode: 1003, RemoteIP: net.ParseIP("127.0.0.1"), RemotePort: 8080, State: "ESTABLISHED"},   // local, ignored
			{Proto: "tcp", Inode: 9999, RemoteIP: net.ParseIP("8.8.8.8"), RemotePort: 443, State: "ESTABLISHED"},      // not owned, ignored
		},
	}
	fs, _ := FDSocket{}.Inspect(target)
	act := activeByTech(fs)
	f, ok := act[model.TechUnexpectedDest]
	if !ok {
		t.Fatal("expected unexpected-dest finding")
	}
	if f.Evidence["ip"] != "203.0.113.9" {
		t.Errorf("flagged wrong dest: %v", f.Evidence["ip"])
	}
	if len(act) != 1 {
		t.Errorf("only the C2 dest should be active, got %d active findings", len(act))
	}
}

func TestFDSocketSensitivePath(t *testing.T) {
	base := &model.Snapshot{FDs: []model.FDRule{{PathPrefix: "/data/data/com.app/"}}}
	target := &Target{
		Desc:     model.TargetDesc{PID: 201},
		Baseline: base,
		FDs: []procfs.FD{
			{Num: 3, Target: "/data/data/com.app/db.sqlite"}, // allowed prefix
			{Num: 4, Target: "/dev/kmem"},                    // sensitive
			{Num: 5, Target: "socket:[12345]"},               // not a path, ignored
		},
	}
	fs, _ := FDSocket{}.Inspect(target)
	act := activeByTech(fs)
	f, ok := act[model.TechSensitiveFD]
	if !ok {
		t.Fatal("expected sensitive-fd finding")
	}
	if f.Evidence["target"] != "/dev/kmem" {
		t.Errorf("flagged wrong fd: %v", f.Evidence["target"])
	}
}
