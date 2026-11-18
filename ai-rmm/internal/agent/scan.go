package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

var defaultScanPorts = []int{22, 23, 80, 443, 445, 3389, 8080, 8443, 9100}

type scanHost struct {
	IP        string   `json:"ip"`
	Names     []string `json:"names,omitempty"`
	PingMs    *float64 `json:"ping_ms,omitempty"`
	OpenPorts []int    `json:"open_ports,omitempty"`
	SysName   string   `json:"snmp_sys_name,omitempty"`
	SysDescr  string   `json:"snmp_sys_descr,omitempty"`
	Guess     string   `json:"guess,omitempty"`
}

func nativeNetworkScan(ctx context.Context, a *Agent, job *protocol.Job) (interface{}, error) {
	var p struct {
		CIDR      string `json:"cidr"`
		Ports     []int  `json:"ports"`
		Ping      *bool  `json:"ping"`
		TimeoutMs int    `json:"timeout_ms"`
	}
	if err := json.Unmarshal(job.Params, &p); err != nil {
		return nil, err
	}
	ips, err := expandCIDR(p.CIDR, 1024)
	if err != nil {
		return nil, err
	}
	if len(p.Ports) == 0 {
		p.Ports = defaultScanPorts
	}
	doPing := p.Ping == nil || *p.Ping
	tmo := time.Duration(p.TimeoutMs) * time.Millisecond
	if tmo <= 0 {
		tmo = 800 * time.Millisecond
	}
	var snmpAuth *protocol.SNMPAuth
	if job.Secrets["snmp_version"] != "" {
		snmpAuth = &protocol.SNMPAuth{Version: job.Secrets["snmp_version"], Community: job.Secrets["snmp_community"], Username: job.Secrets["snmp_username"],
			AuthProto: job.Secrets["snmp_auth_proto"], AuthPass: job.Secrets["snmp_auth_pass"], PrivProto: job.Secrets["snmp_priv_proto"], PrivPass: job.Secrets["snmp_priv_pass"]}
	}

	var mu sync.Mutex
	var found []scanHost
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			h := scanHost{IP: ip}
			alive := false
			if doPing {
				if ms, ok := pingOnce(ctx, ip, tmo); ok {
					h.PingMs = &ms
					alive = true
				}
			}
			for _, port := range p.Ports {
				open, refused := tcpProbe(ctx, ip, port, tmo)
				if open {
					h.OpenPorts = append(h.OpenPorts, port)
				}
				// A RST means something is there even with no open ports.
				alive = alive || open || refused
			}
			if snmpAuth != nil {
				if snap, err := snmpSystem(ip, snmpAuth, tmo*2, 0); err == nil {
					h.SysName, h.SysDescr = snap.SysName, firstLine(snap.SysDescr)
					alive = true
				}
			}
			if !alive {
				return
			}
			rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if names, err := net.DefaultResolver.LookupAddr(rctx, ip); err == nil {
				for _, n := range names {
					h.Names = append(h.Names, strings.TrimSuffix(n, "."))
				}
			}
			cancel()
			h.Guess = guessKind(h)
			mu.Lock()
			found = append(found, h)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool { return ipLess(found[i].IP, found[j].IP) })
	return map[string]interface{}{"cidr": p.CIDR, "scanned": len(ips), "alive": len(found), "hosts": found}, nil
}

func expandCIDR(cidr string, max int) ([]string, error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return nil, errors.New("cidr must be IPv4, e.g. 10.0.0.0/24")
	}
	ones, bits := n.Mask.Size()
	size := 1 << uint(bits-ones)
	if size > max {
		return nil, fmt.Errorf("subnet larger than %d addresses", max)
	}
	base := n.IP.To4()
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	var out []string
	for i := 0; i < size; i++ {
		if size > 2 && (i == 0 || i == size-1) { // network & broadcast
			continue
		}
		v := start + uint32(i)
		out = append(out, fmt.Sprintf("%d.%d.%d.%d", v>>24, v>>16&0xff, v>>8&0xff, v&0xff))
	}
	return out, nil
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// tcpProbe reports open, and refused (host answered with RST).
func tcpProbe(ctx context.Context, ip string, port int, tmo time.Duration) (open, refused bool) {
	d := net.Dialer{Timeout: tmo}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err == nil {
		c.Close()
		return true, false
	}
	return false, errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "refused")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func guessKind(h scanHost) string {
	d := strings.ToLower(h.SysDescr + " " + h.SysName + " " + strings.Join(h.Names, " "))
	has := func(p int) bool {
		for _, x := range h.OpenPorts {
			if x == p {
				return true
			}
		}
		return false
	}
	switch {
	case containsAny(d, "fortigate", "pfsense", "sonicwall", "palo alto", "pan-os", "asa", "watchguard", "sophos", "meraki mx", "opnsense"):
		return "firewall"
	case containsAny(d, "access point", "aironet", "unifi ap", "uap", "aruba ap", "instant on", "wap", "meraki mr", "ruckus"):
		return "ap"
	case containsAny(d, "wireless lan controller", "wlc"):
		return "wlc"
	case containsAny(d, "switch", "catalyst", "procurve", "aruba", "edgeswitch", "usw", "netgear", "cisco ios", "comware", "meraki ms", "dell networking"):
		return "switch"
	case containsAny(d, "routeros", "mikrotik", "edgerouter", "router"):
		return "router"
	case containsAny(d, "apc", "ups", "eaton", "smart-ups", "powerware", "cyberpower"):
		return "ups"
	case containsAny(d, "printer", "zebra", "jetdirect", "laserjet", "lexmark", "ricoh", "xerox", "brother", "kyocera", "canon"), has(9100):
		return "printer"
	case containsAny(d, "siemens", "simatic", "rockwell", "allen-bradley", "schneider", "modicon", "omron", "beckhoff", "moxa", "prosoft"), has(502), has(102), has(44818):
		return "plc_or_industrial"
	case containsAny(d, "camera", "axis", "hikvision", "dahua", "nvr"):
		return "camera"
	case has(3389) && has(445):
		return "windows"
	case has(445):
		return "windows_or_nas"
	case has(22):
		return "linux_or_network_device"
	}
	return "unknown"
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
