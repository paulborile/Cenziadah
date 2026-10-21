// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"strings"
	"testing"
)

func TestParseNetTCP(t *testing.T) {
	// One established connection: local 127.0.0.1:54321, remote 93.184.216.34:443.
	// 127.0.0.1 little-endian hex = 0100007F ; port 54321 = D431
	// 93.184.216.34 little-endian = 22D8B85D ; port 443 = 01BB
	fixture := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:D431 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 987654 1 ffff 100\n"
	socks, err := parseNet(strings.NewReader(fixture), "tcp")
	if err != nil {
		t.Fatalf("parseNet: %v", err)
	}
	if len(socks) != 1 {
		t.Fatalf("got %d sockets, want 1", len(socks))
	}
	s := socks[0]
	if s.LocalIP.String() != "127.0.0.1" || s.LocalPort != 54321 {
		t.Errorf("local = %s:%d, want 127.0.0.1:54321", s.LocalIP, s.LocalPort)
	}
	if s.RemoteIP.String() != "93.184.216.34" || s.RemotePort != 443 {
		t.Errorf("remote = %s:%d, want 93.184.216.34:443", s.RemoteIP, s.RemotePort)
	}
	if s.State != "ESTABLISHED" {
		t.Errorf("state = %q, want ESTABLISHED", s.State)
	}
	if s.Inode != 987654 {
		t.Errorf("inode = %d, want 987654", s.Inode)
	}
}
