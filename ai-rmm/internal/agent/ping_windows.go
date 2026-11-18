//go:build windows

package agent

import (
	"context"
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
)

// pingOnce sends one ICMP echo via the ICMP helper API, which works for
// unprivileged processes and needs no raw sockets.
func pingOnce(ctx context.Context, host string, timeout time.Duration) (float64, bool) {
	ip, err := resolve4(ctx, host)
	if err != nil {
		return 0, false
	}
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return 0, false
	}
	defer procIcmpCloseHandle.Call(h)
	payload := []byte("airmm-ping-0123456789abcdef")
	reply := make([]byte, 128+len(payload))
	dst := binary.LittleEndian.Uint32(ip) // IPAddr is in network order in memory
	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(h, uintptr(dst),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if n == 0 {
		return 0, false
	}
	status := binary.LittleEndian.Uint32(reply[4:8])
	if status != 0 { // IP_SUCCESS
		return 0, false
	}
	rtt := float64(binary.LittleEndian.Uint32(reply[8:12]))
	if rtt == 0 {
		rtt = float64(time.Since(start).Microseconds()) / 1000
	}
	return rtt, true
}

func resolve4(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host).To4(); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	return ips[0].To4(), nil
}
