// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"strings"
	"testing"
)

func TestParseMaps(t *testing.T) {
	const fixture = `55a1b2c00000-55a1b2c01000 r-xp 00001000 08:01 131073 /usr/bin/victim
7f0000000000-7f0000001000 rwxp 00000000 00:00 0 
7f1111111000-7f1111112000 r-xp 00000000 08:01 262145 /tmp/stale.so (deleted)
7f2222222000-7f2222223000 r-xp 00000000 00:00 0 [vdso]
7f3333333000-7f3333334000 rw-p 00000000 00:00 0 memfd:jit-cache (deleted)
7f4444444000-7f4444445000 r--p 00000000 08:01 999 /lib/x86_64-linux-gnu/libc.so.6`

	regs, err := parseMaps(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseMaps: %v", err)
	}
	if len(regs) != 6 {
		t.Fatalf("got %d regions, want 6", len(regs))
	}

	// Line 1: normal file-backed code
	if got := regs[0]; got.Path != "/usr/bin/victim" || !got.Exec || got.Write || !got.FileBacked() {
		t.Errorf("reg0 unexpected: %+v (perms=%s)", got, got.Perms())
	}
	if regs[0].Offset != 0x1000 {
		t.Errorf("reg0 offset = %#x, want 0x1000", regs[0].Offset)
	}

	// Line 2: anonymous RWX (the classic injection IoC)
	if got := regs[1]; !(got.Read && got.Write && got.Exec) {
		t.Errorf("reg1 should be rwx, got %s", got.Perms())
	}
	if regs[1].FileBacked() {
		t.Errorf("reg1 anon should not be file-backed")
	}

	// Line 3: deleted backing, executable
	if got := regs[2]; !got.Deleted || got.Path != "/tmp/stale.so" || got.FileBacked() {
		t.Errorf("reg2 deleted-backing parse wrong: %+v", got)
	}

	// Line 4: [vdso] pseudo mapping is not file-backed
	if regs[3].FileBacked() {
		t.Errorf("reg3 [vdso] should not be file-backed")
	}

	// Line 5: memfd (deleted) is not file-backed
	if regs[4].FileBacked() {
		t.Errorf("reg4 memfd should not be file-backed")
	}

	// Line 6: libc, size and inode parsed
	if regs[5].Size() != 0x1000 || regs[5].Inode != 999 {
		t.Errorf("reg5 size/inode wrong: size=%#x inode=%d", regs[5].Size(), regs[5].Inode)
	}
}

func TestParseMapLineGarbage(t *testing.T) {
	for _, bad := range []string{"", "not a maps line", "zzz-zzz r-xp"} {
		if _, ok := parseMapLine(bad); ok {
			t.Errorf("expected parse failure for %q", bad)
		}
	}
}

func TestParseStartBrk(t *testing.T) {
	// fields 3..52 of a real /proc/<pid>/stat; start_brk (field 47) = 110230050590720 = 0x6440ef025000
	stat := "733999 (obsidian) S 733842 733842 4598 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 20 0 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0 1 2 110230050590720 4 5 6 7 0"
	got, ok := parseStartBrk(stat)
	if !ok || got != 0x6440ef025000 {
		t.Errorf("parseStartBrk = %#x %v", got, ok)
	}
	if _, ok := parseStartBrk("1 (x) S 0"); ok {
		t.Error("short stat must not parse")
	}
}

func TestRegionAnonymous(t *testing.T) {
	for _, c := range []struct {
		r    Region
		want bool
	}{
		{Region{}, true},
		{Region{Path: "[anon:v8]"}, true},
		{Region{Path: "[heap]", NotBrkHeap: true}, true},
		{Region{Path: "[heap]"}, false},
		{Region{Path: "[stack]"}, false},
		{Region{Path: "/usr/lib/libc.so.6"}, false},
		{Region{Path: "memfd:jit (deleted)", Deleted: true}, false},
	} {
		if got := c.r.Anonymous(); got != c.want {
			t.Errorf("%+v.Anonymous() = %v, want %v", c.r, got, c.want)
		}
	}
}
