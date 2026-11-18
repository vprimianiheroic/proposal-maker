package agent

import (
	"net"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/airmm/airmm/internal/protocol"
)

// CollectFacts gathers cheap, native inventory (no PowerShell) for heartbeats.
func CollectFacts() protocol.Facts {
	f := protocol.Facts{Arch: runtime.GOARCH, OSArch: runtime.GOARCH, CPUs: runtime.NumCPU()}
	f.Hostname, _ = os.Hostname()
	if i := strings.IndexByte(f.Hostname, '.'); i > 0 {
		f.Hostname = f.Hostname[:i]
	}
	f.IPs, f.MACs = addresses()
	platformFacts(&f)
	return f
}

func addresses() (ips, macs []string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		got := false
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
				continue
			}
			ips = append(ips, ipn.IP.String())
			got = true
		}
		if got && len(ifc.HardwareAddr) > 0 {
			macs = append(macs, ifc.HardwareAddr.String())
		}
	}
	sort.Strings(ips)
	return ips, macs
}
