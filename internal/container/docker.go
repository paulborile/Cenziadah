// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package container reads what the container runtime has configured for a
// container, from the runtime's own root-owned state on the host. It is a
// platform layer (like procfs for /proc): it wraps Docker's on-disk format so
// nothing else depends on it. All input is trusted operator/runtime state, read
// with a size bound.
package container

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxStateFile bounds how much of a state file is read (memory budget).
const maxStateFile = 4 << 20

// DefaultDockerRoot is Docker's data root unless daemon.json sets "data-root".
const DefaultDockerRoot = "/var/lib/docker"

var containerID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ShimContainerID returns the container ID a containerd shim serves, from its
// command line ("... -id <64 hex> ..."), or "" if there is none.
func ShimContainerID(cmdline string) string {
	f := strings.Fields(cmdline)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "-id" && containerID.MatchString(f[i+1]) {
			return f[i+1]
		}
	}
	return ""
}

// DockerRoot returns Docker's data root: "data-root" from daemonJSON (normally
// /etc/docker/daemon.json) if set, else DefaultDockerRoot.
func DockerRoot(daemonJSON string) string {
	var cfg struct {
		DataRoot string `json:"data-root"`
	}
	if b, err := readBounded(daemonJSON); err == nil && json.Unmarshal(b, &cfg) == nil && filepath.IsAbs(cfg.DataRoot) {
		return cfg.DataRoot
	}
	return DefaultDockerRoot
}

// Healthcheck describes the healthcheck Docker runs inside a container.
type Healthcheck struct {
	// Cmdline is the process command line as /proc/<pid>/cmdline shows it
	// (arguments joined by spaces).
	Cmdline string
	// Program is the base name of the program run (CMD form), or "" for the
	// CMD-SHELL form, which runs a shell.
	Program string
}

// HealthcheckOf returns the healthcheck of container id (zero value if none).
func HealthcheckOf(dockerRoot, id string) (Healthcheck, error) {
	cmd, err := HealthcheckCmdline(dockerRoot, id)
	if err != nil || cmd == "" {
		return Healthcheck{}, err
	}
	hc := Healthcheck{Cmdline: cmd}
	if !strings.HasPrefix(cmd, "/bin/sh -c ") {
		hc.Program = filepath.Base(strings.Fields(cmd)[0])
	}
	return hc, nil
}

// HealthcheckCmdline returns the command line, as /proc/<pid>/cmdline shows it
// (arguments joined by spaces), of the healthcheck Docker runs inside container
// id, or "" when it has none. CMD-SHELL runs `/bin/sh -c <cmd>`; CMD runs the
// arguments directly.
func HealthcheckCmdline(dockerRoot, id string) (string, error) {
	if !containerID.MatchString(id) {
		return "", errors.New("container: invalid id")
	}
	b, err := readBounded(filepath.Join(dockerRoot, "containers", id, "config.v2.json"))
	if err != nil {
		return "", err
	}
	var st struct {
		Config struct {
			Healthcheck *struct {
				Test []string `json:"Test"`
			} `json:"Healthcheck"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return "", err
	}
	hc := st.Config.Healthcheck
	if hc == nil || len(hc.Test) < 2 {
		return "", nil // none, or ["NONE"]
	}
	switch hc.Test[0] {
	case "CMD-SHELL":
		return "/bin/sh -c " + strings.Join(hc.Test[1:], " "), nil
	case "CMD":
		return strings.Join(hc.Test[1:], " "), nil
	}
	return "", nil
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStateFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxStateFile {
		return nil, errors.New("container: state file too large")
	}
	return b, nil
}
