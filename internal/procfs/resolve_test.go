// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveBackingPathHostNative(t *testing.T) {
	// For a host-native process a real file must resolve to a readable path naming
	// the SAME bytes. (It may come back as /proc/self/root/<path>, which for a process
	// in the host mount namespace is the identical file.)
	dir := t.TempDir()
	f := filepath.Join(dir, "libx.so")
	os.WriteFile(f, []byte("\x7fELF-marker"), 0o644)
	got, ok := ResolveBackingPath(os.Getpid(), f)
	if !ok {
		t.Fatal("expected host file to resolve")
	}
	b, err := os.ReadFile(got)
	if err != nil || string(b) != "\x7fELF-marker" {
		t.Errorf("resolved path %q does not read back the original file (err=%v)", got, err)
	}
}

func TestResolveBackingPathMissing(t *testing.T) {
	if _, ok := ResolveBackingPath(os.Getpid(), "/no/such/container/path.so"); ok {
		t.Error("expected unresolved for nonexistent path")
	}
}

func TestResolveBackingPathRejectsRelative(t *testing.T) {
	if _, ok := ResolveBackingPath(1, "relative/path.so"); ok {
		t.Error("relative paths must not resolve")
	}
	if _, ok := ResolveBackingPath(1, ""); ok {
		t.Error("empty path must not resolve")
	}
}

func TestIsELFCodeLib(t *testing.T) {
	cases := map[string]bool{
		"/data/.../libwhatsapp.so":   true,
		"/system/lib64/libc.so":      true,
		"/usr/lib/libc.so.6":         true,
		"/usr/bin/app_process64":     true, // extension-less executable
		"/system/framework/boot.oat": false,
		"/x/base.apk":                false,
		"/x/classes.vdex":            false,
		"/x/foo.art":                 false,
	}
	for p, want := range cases {
		if got := IsELFCodeLib(p); got != want {
			t.Errorf("IsELFCodeLib(%q)=%v, want %v", p, got, want)
		}
	}
}

// Regression (production false CRITICAL): for a process whose root and mount
// namespace can no longer be read (it exited, or another namespace), the host
// file at the same path must NOT be used: it is a different file.
func TestResolveBackingPathNoHostFallbackForOtherNamespace(t *testing.T) {
	const gone = 4194000
	if _, err := os.Stat("/proc/4194000"); err == nil {
		t.Skip("pid unexpectedly exists")
	}
	if p, ok := ResolveBackingPath(gone, "/usr/bin/ls"); ok {
		t.Errorf("exited/unknown-namespace process resolved to host file %q", p)
	}
	if TrustedPath(gone, "/usr/bin/ls") {
		t.Error("TrustedPath must not judge an unknown namespace by the host file")
	}
}

func TestSameMountNamespace(t *testing.T) {
	if !SameMountNamespace(os.Getpid()) {
		t.Error("our own process shares our mount namespace")
	}
	if SameMountNamespace(4194000) {
		t.Error("a non-existent process cannot be confirmed")
	}
}
