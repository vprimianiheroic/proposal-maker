package agent

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/airmm/airmm/internal/protocol"
)

const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidSysContact  = ".1.3.6.1.2.1.1.4.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidSysLocation = ".1.3.6.1.2.1.1.6.0"

	oidIfDescr       = ".1.3.6.1.2.1.2.2.1.2"
	oidIfAdminStatus = ".1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus  = ".1.3.6.1.2.1.2.2.1.8"
	oidIfInErrors    = ".1.3.6.1.2.1.2.2.1.14"
	oidIfOutErrors   = ".1.3.6.1.2.1.2.2.1.20"
	oidIfName        = ".1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOctets  = ".1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets = ".1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed   = ".1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias       = ".1.3.6.1.2.1.31.1.1.1.18"
)

func snmpClient(addr string, auth *protocol.SNMPAuth, timeout time.Duration, retries int) (*gosnmp.GoSNMP, error) {
	port := uint16(161)
	if auth.Port > 0 {
		port = uint16(auth.Port)
	}
	g := &gosnmp.GoSNMP{Target: addr, Port: port, Timeout: timeout, Retries: retries, MaxOids: 60, MaxRepetitions: 25}
	switch auth.Version {
	case "", "2c":
		g.Version, g.Community = gosnmp.Version2c, auth.Community
	case "3":
		g.Version, g.SecurityModel = gosnmp.Version3, gosnmp.UserSecurityModel
		usm := &gosnmp.UsmSecurityParameters{UserName: auth.Username}
		g.MsgFlags = gosnmp.NoAuthNoPriv
		if auth.AuthPass != "" {
			g.MsgFlags = gosnmp.AuthNoPriv
			usm.AuthenticationPassphrase = auth.AuthPass
			switch strings.ToUpper(auth.AuthProto) {
			case "MD5":
				usm.AuthenticationProtocol = gosnmp.MD5
			case "SHA256":
				usm.AuthenticationProtocol = gosnmp.SHA256
			case "SHA512":
				usm.AuthenticationProtocol = gosnmp.SHA512
			default:
				usm.AuthenticationProtocol = gosnmp.SHA
			}
			if auth.PrivPass != "" {
				g.MsgFlags = gosnmp.AuthPriv
				usm.PrivacyPassphrase = auth.PrivPass
				switch strings.ToUpper(auth.PrivProto) {
				case "DES":
					usm.PrivacyProtocol = gosnmp.DES
				case "AES256":
					usm.PrivacyProtocol = gosnmp.AES256
				default:
					usm.PrivacyProtocol = gosnmp.AES
				}
			}
		}
		g.SecurityParameters = usm
	default:
		return nil, fmt.Errorf("unsupported SNMP version %q", auth.Version)
	}
	return g, g.Connect()
}

func snmpString(v gosnmp.SnmpPDU) string {
	switch x := v.Value.(type) {
	case []byte:
		return string(x)
	case string:
		return x
	case nil:
		return ""
	}
	return fmt.Sprint(v.Value)
}

// snmpSystem reads the system group, and the interface table when walkIfaces > 0.
func snmpSystem(addr string, auth *protocol.SNMPAuth, timeout time.Duration, walkIfaces int) (*protocol.SNMPSnapshot, error) {
	g, err := snmpClient(addr, auth, timeout, 1)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	pkt, err := g.Get([]string{oidSysDescr, oidSysUpTime, oidSysContact, oidSysName, oidSysLocation})
	if err != nil {
		return nil, err
	}
	snap := &protocol.SNMPSnapshot{OK: true}
	got := false
	for _, v := range pkt.Variables {
		if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.Null {
			continue
		}
		got = true
		switch v.Name {
		case oidSysDescr:
			snap.SysDescr = strings.TrimSpace(snmpString(v))
		case oidSysUpTime:
			snap.SysUptimeS = gosnmp.ToBigInt(v.Value).Int64() / 100
		case oidSysContact:
			snap.Contact = snmpString(v)
		case oidSysName:
			snap.SysName = snmpString(v)
		case oidSysLocation:
			snap.Location = snmpString(v)
		}
	}
	if !got {
		return nil, errors.New("no SNMP system data (wrong community/credentials or view?)")
	}
	if walkIfaces > 0 {
		snap.Interfaces, err = snmpInterfaces(g, walkIfaces)
		if err != nil {
			snap.Error = "interface walk: " + err.Error()
		}
	}
	return snap, nil
}

func snmpInterfaces(g *gosnmp.GoSNMP, max int) ([]protocol.Interface, error) {
	byIdx := map[int]*protocol.Interface{}
	var order []int
	get := func(idx int) *protocol.Interface {
		if i, ok := byIdx[idx]; ok {
			return i
		}
		if len(order) >= max {
			return nil
		}
		i := &protocol.Interface{Index: idx}
		byIdx[idx] = i
		order = append(order, idx)
		return i
	}
	walk := func(base string, set func(*protocol.Interface, gosnmp.SnmpPDU)) error {
		var pdus []gosnmp.SnmpPDU
		var err error
		if g.Version == gosnmp.Version1 {
			pdus, err = g.WalkAll(base)
		} else {
			pdus, err = g.BulkWalkAll(base)
		}
		if err != nil {
			return err
		}
		for _, p := range pdus {
			idx, err := strconv.Atoi(p.Name[strings.LastIndexByte(p.Name, '.')+1:])
			if err != nil {
				continue
			}
			if i := get(idx); i != nil {
				set(i, p)
			}
		}
		return nil
	}
	u := func(p gosnmp.SnmpPDU) uint64 { return gosnmp.ToBigInt(p.Value).Uint64() }
	if err := walk(oidIfDescr, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.Name = snmpString(p) }); err != nil {
		return nil, err
	}
	_ = walk(oidIfName, func(i *protocol.Interface, p gosnmp.SnmpPDU) {
		if n := snmpString(p); n != "" {
			i.Name = n
		}
	})
	_ = walk(oidIfAlias, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.Alias = snmpString(p) })
	_ = walk(oidIfAdminStatus, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.AdminUp = u(p) == 1 })
	_ = walk(oidIfOperStatus, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.OperUp = u(p) == 1 })
	_ = walk(oidIfHighSpeed, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.SpeedMbps = u(p) })
	_ = walk(oidIfInErrors, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.InErrors = u(p) })
	_ = walk(oidIfOutErrors, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.OutErrors = u(p) })
	_ = walk(oidIfHCInOctets, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.InOctets = u(p) })
	_ = walk(oidIfHCOutOctets, func(i *protocol.Interface, p gosnmp.SnmpPDU) { i.OutOctets = u(p) })
	out := make([]protocol.Interface, 0, len(order))
	for _, idx := range order {
		out = append(out, *byIdx[idx])
	}
	return out, nil
}
