// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Socket is one connection from /proc/<pid>/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto      string // "tcp","tcp6","udp","udp6"
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string // hex state (TCP); "" for udp
	Inode      uint64 // socket inode, to join against /proc/<pid>/fd
}

// tcpStates maps the hex state codes used in /proc/net/tcp.
var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// ReadSockets parses the per-process network tables for the four common protos.
func ReadSockets(pid int) ([]Socket, error) {
	base := "/proc/" + strconv.Itoa(pid) + "/net/"
	var all []Socket
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(base + proto)
		if err != nil {
			continue // proto table may be absent; skip
		}
		socks, perr := parseNet(f, proto)
		f.Close()
		if perr != nil {
			return nil, perr
		}
		all = append(all, socks...)
	}
	return all, nil
}

func parseNet(r io.Reader, proto string) ([]Socket, error) {
	var socks []Socket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false // header row
			continue
		}
		s, ok := parseNetLine(sc.Text(), proto)
		if ok {
			socks = append(socks, s)
		}
	}
	return socks, sc.Err()
}

// parseNetLine parses one row. Columns of interest:
//
//	sl  local_address rem_address st ... inode
func parseNetLine(line, proto string) (Socket, bool) {
	f := strings.Fields(line)
	if len(f) < 10 {
		return Socket{}, false
	}
	lip, lport, ok1 := parseHexAddr(f[1])
	rip, rport, ok2 := parseHexAddr(f[2])
	if !ok1 || !ok2 {
		return Socket{}, false
	}
	inode, _ := strconv.ParseUint(f[9], 10, 64)
	s := Socket{
		Proto:      proto,
		LocalIP:    lip,
		LocalPort:  lport,
		RemoteIP:   rip,
		RemotePort: rport,
		Inode:      inode,
	}
	if strings.HasPrefix(proto, "tcp") {
		s.State = tcpStates[strings.ToUpper(f[3])]
	}
	return s, true
}

// parseHexAddr decodes the "HEXIP:HEXPORT" field. IPv4 is 8 hex chars (little-
// endian), IPv6 is 32 hex chars (4 little-endian 32-bit words).
func parseHexAddr(s string) (net.IP, int, bool) {
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return nil, 0, false
	}
	hexIP := s[:colon]
	port64, err := strconv.ParseUint(s[colon+1:], 16, 32)
	if err != nil {
		return nil, 0, false
	}
	switch len(hexIP) {
	case 8:
		v, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return nil, 0, false
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, uint32(v))
		return ip, int(port64), true
	case 32:
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			word, err := strconv.ParseUint(hexIP[i*8:i*8+8], 16, 32)
			if err != nil {
				return nil, 0, false
			}
			binary.LittleEndian.PutUint32(ip[i*4:], uint32(word))
		}
		return ip, int(port64), true
	default:
		return nil, 0, false
	}
}
