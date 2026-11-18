package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/airmm/airmm/internal/protocol"
)

// NetDevice is a network device (switch, AP, firewall, UPS, printer, PLC
// gateway...) watched by a chosen agent acting as collector.
type NetDevice struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	Address          string       `json:"address"`
	Kind             string       `json:"kind"`
	CollectorAgentID string       `json:"collector_agent_id"`
	IntervalSec      int          `json:"interval_sec"`
	Ping             bool         `json:"ping"`
	TCPPorts         []int        `json:"tcp_ports,omitempty"`
	SNMPCredential   string       `json:"snmp_credential,omitempty"`
	Notes            string       `json:"notes,omitempty"`
	CreatedBy        string       `json:"created_by"`
	CreatedAt        int64        `json:"created_at"`
	Status           DeviceStatus `json:"status"`
	History          []Sample     `json:"history,omitempty"`
}

type DeviceStatus struct {
	State            string                 `json:"state"` // unknown | up | down | stale
	LastCheck        int64                  `json:"last_check,omitempty"`
	LastChange       int64                  `json:"last_change,omitempty"`
	LatencyMs        float64                `json:"latency_ms,omitempty"`
	PingOK           *bool                  `json:"ping_ok,omitempty"`
	Ports            map[int]bool           `json:"ports,omitempty"`
	SNMP             *protocol.SNMPSnapshot `json:"snmp,omitempty"`
	Interfaces       []protocol.Interface   `json:"interfaces,omitempty"`
	InterfacesAt     int64                  `json:"interfaces_at,omitempty"`
	Error            string                 `json:"error,omitempty"`
	ConsecutiveFails int                    `json:"consecutive_fails,omitempty"`
}

type Sample struct {
	T  int64   `json:"t"`
	Up bool    `json:"up"`
	Ms float64 `json:"ms,omitempty"`
}

const maxHistory = 1440 // 24h at 60s

var deviceKinds = map[string]bool{"switch": true, "ap": true, "wlc": true, "firewall": true, "router": true, "ups": true, "printer": true, "server": true, "plc": true, "camera": true, "other": true}

func (s *Server) SaveDevice(c Caller, d *NetDevice) (*NetDevice, error) {
	d.Name = strings.TrimSpace(d.Name)
	if d.Name == "" {
		return nil, errors.New("name is required")
	}
	if !hostRe.MatchString(d.Address) {
		return nil, errors.New("address must be a hostname or IPv4 address")
	}
	d.Kind = strings.ToLower(d.Kind)
	if d.Kind == "" {
		d.Kind = "other"
	}
	if !deviceKinds[d.Kind] {
		return nil, fmt.Errorf("kind must be one of switch, ap, wlc, firewall, router, ups, printer, server, plc, camera, other")
	}
	if d.IntervalSec == 0 {
		d.IntervalSec = 60
	}
	if d.IntervalSec < 30 || d.IntervalSec > 3600 {
		return nil, errors.New("interval_sec must be 30-3600")
	}
	for _, p := range d.TCPPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %d", p)
		}
	}
	if !d.Ping && len(d.TCPPorts) == 0 && d.SNMPCredential == "" {
		d.Ping = true
	}
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	ct := strings.ToLower(strings.TrimSpace(d.CollectorAgentID))
	if ct == "" || ct == "all" || strings.HasPrefix(ct, "group:") {
		return nil, errors.New("collector must be one specific agent (ID or hostname)")
	}
	agents, err := s.resolveTargetsLocked([]string{d.CollectorAgentID})
	if err != nil {
		return nil, fmt.Errorf("collector: %w", err)
	}
	d.CollectorAgentID = agents[0].ID
	if d.SNMPCredential != "" {
		if _, err := s.credentialLocked(d.SNMPCredential, CredSNMP); err != nil {
			return nil, err
		}
	}
	if d.ID == "" {
		d.ID = newID("d")
		d.CreatedBy, d.CreatedAt = c.String(), now()
		d.Status = DeviceStatus{State: "unknown"}
	} else {
		old, ok := s.store.st.Devices[d.ID]
		if !ok {
			return nil, errors.New("no such device")
		}
		d.CreatedBy, d.CreatedAt, d.Status, d.History = old.CreatedBy, old.CreatedAt, old.Status, old.History
	}
	s.store.st.Devices[d.ID] = d
	s.store.markDirty()
	go s.Audit(c.String(), "device.save", map[string]interface{}{"id": d.ID, "name": d.Name, "address": d.Address, "collector": d.CollectorAgentID})
	go s.wakeAgent(d.CollectorAgentID)
	cp := *d
	return &cp, nil
}

func (s *Server) DeleteDevice(c Caller, id string) error {
	s.store.mu.Lock()
	d, ok := s.store.st.Devices[id]
	delete(s.store.st.Devices, id)
	s.store.markDirty()
	s.store.mu.Unlock()
	if !ok {
		return errors.New("no such device")
	}
	s.Audit(c.String(), "device.delete", map[string]string{"id": id, "name": d.Name})
	s.wakeAgent(d.CollectorAgentID)
	return nil
}

// ListDevices returns devices without history (use GetDevice for that).
func (s *Server) ListDevices(state string) []*NetDevice {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	out := []*NetDevice{}
	for _, d := range s.store.st.Devices {
		if state != "" && d.Status.State != state {
			continue
		}
		c := *d
		c.History = nil
		c.Status.Interfaces = nil
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Server) GetDevice(idOrName string) (*NetDevice, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	for _, d := range s.store.st.Devices {
		if d.ID == idOrName || strings.EqualFold(d.Name, idOrName) || strings.EqualFold(d.Address, idOrName) {
			c := *d
			c.History = append([]Sample(nil), d.History...)
			return &c, nil
		}
	}
	return nil, errors.New("no such device")
}

// monitorConfigLocked builds the collector assignment for one agent.
func (s *Server) monitorConfigLocked(agentID string) *protocol.MonitorConfig {
	cfg := &protocol.MonitorConfig{Devices: []protocol.MonitorTarget{}}
	for _, d := range s.store.st.Devices {
		if d.CollectorAgentID != agentID {
			continue
		}
		t := protocol.MonitorTarget{ID: d.ID, Name: d.Name, Address: d.Address, IntervalSec: d.IntervalSec, Ping: d.Ping, TCPPorts: d.TCPPorts}
		if d.SNMPCredential != "" {
			if sec, err := s.credentialLocked(d.SNMPCredential, CredSNMP); err == nil {
				t.SNMP = snmpAuthFrom(sec)
			}
		}
		cfg.Devices = append(cfg.Devices, t)
	}
	sort.Slice(cfg.Devices, func(i, j int) bool { return cfg.Devices[i].ID < cfg.Devices[j].ID })
	b, _ := json.Marshal(cfg.Devices)
	h := sha256.Sum256(append(s.vaultKey, b...)) // keyed so the version leaks nothing about secrets
	cfg.Version = hex.EncodeToString(h[:8])
	return cfg
}

type devEvent struct{ typ, sev, subject, text string }

func (s *Server) ingestMonitor(agentID string, reports []protocol.MonitorReport) {
	var evs []devEvent
	s.store.mu.Lock()
	for i := range reports {
		r := &reports[i]
		d, ok := s.store.st.Devices[r.DeviceID]
		if !ok || d.CollectorAgentID != agentID {
			continue
		}
		st := &d.Status
		prev := st.State
		st.LastCheck = r.Time
		st.LatencyMs, st.PingOK, st.Ports, st.Error = r.LatencyMs, r.PingOK, r.Ports, r.Error
		if r.SNMP != nil {
			if r.SNMP.Interfaces != nil {
				evs = append(evs, interfaceChanges(d, st.Interfaces, r.SNMP.Interfaces)...)
				st.Interfaces, st.InterfacesAt = r.SNMP.Interfaces, r.Time
			}
			snap := *r.SNMP
			snap.Interfaces = nil
			st.SNMP = &snap
		}
		if r.Up {
			st.ConsecutiveFails = 0
			if prev != "up" {
				st.State, st.LastChange = "up", r.Time
				if prev == "down" {
					evs = append(evs, devEvent{"device_up", "info", d.Name, fmt.Sprintf("%s (%s, %s) is back up", d.Name, d.Kind, d.Address)})
				}
			}
		} else {
			st.ConsecutiveFails++
			// Two consecutive failures before alerting, to ride out a lost ping.
			if st.ConsecutiveFails >= 2 && prev != "down" {
				st.State, st.LastChange = "down", r.Time
				evs = append(evs, devEvent{"device_down", "critical", d.Name, fmt.Sprintf("%s (%s, %s) is DOWN: %s", d.Name, d.Kind, d.Address, r.Error)})
			} else if prev == "unknown" || prev == "stale" {
				st.State = "unknown"
			}
		}
		d.History = append(d.History, Sample{T: r.Time, Up: r.Up, Ms: r.LatencyMs})
		if len(d.History) > maxHistory {
			d.History = d.History[len(d.History)-maxHistory:]
		}
	}
	s.store.markDirty()
	s.store.mu.Unlock()
	for _, e := range evs {
		s.emit(e.typ, e.sev, e.subject, e.text, nil)
	}
}

// interfaceChanges flags described (aliased) ports that went down while
// administratively up. Unlabelled access ports flap all day as PCs sleep;
// labelled ones are usually uplinks, APs, servers and line equipment.
func interfaceChanges(d *NetDevice, old, cur []protocol.Interface) []devEvent {
	if len(old) == 0 {
		return nil
	}
	was := map[int]protocol.Interface{}
	for _, i := range old {
		was[i.Index] = i
	}
	var evs []devEvent
	for _, i := range cur {
		o, ok := was[i.Index]
		if !ok || i.Alias == "" || !i.AdminUp {
			continue
		}
		if o.OperUp && !i.OperUp {
			evs = append(evs, devEvent{"interface_down", "warning", d.Name, fmt.Sprintf("%s port %s (%s) went down", d.Name, i.Name, i.Alias)})
		} else if !o.OperUp && i.OperUp {
			evs = append(evs, devEvent{"interface_up", "info", d.Name, fmt.Sprintf("%s port %s (%s) is up", d.Name, i.Name, i.Alias)})
		}
	}
	return evs
}

// checkDevicesStale marks devices whose collector stopped reporting.
func (s *Server) checkDevicesStale() {
	t0 := now()
	var evs []devEvent
	s.store.mu.Lock()
	for _, d := range s.store.st.Devices {
		limit := int64(3*d.IntervalSec + 60)
		if d.Status.State != "stale" && d.Status.LastCheck > 0 && t0-d.Status.LastCheck > limit {
			d.Status.State = "stale"
			host := d.CollectorAgentID
			if a, ok := s.store.st.Agents[d.CollectorAgentID]; ok {
				host = a.Hostname
			}
			evs = append(evs, devEvent{"device_stale", "warning", d.Name, fmt.Sprintf("No monitoring data for %s from collector %s; reassign the device or check the collector", d.Name, host)})
			s.store.markDirty()
		}
	}
	s.store.mu.Unlock()
	for _, e := range evs {
		s.emit(e.typ, e.sev, e.subject, e.text, nil)
	}
}
