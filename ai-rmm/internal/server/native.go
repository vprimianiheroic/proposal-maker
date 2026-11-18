package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/airmm/airmm/internal/protocol"
)

// Native tools are implemented inside the agent (Go) rather than as
// PowerShell, because they need things scripts handle badly: SMB sessions
// with explicit credentials, remote service control, fast concurrent
// network probing, SNMP.

func nativeTools() map[string]*Tool {
	mk := func(name, desc string, risk protocol.Risk, timeout int, params string) *Tool {
		return &Tool{Name: name, Description: desc, Risk: risk, TimeoutSec: timeout, Params: json.RawMessage(params),
			Kind: "native", Source: "builtin", Status: ToolPublished, Version: 1,
			Script: "(native: implemented in the agent binary)"}
	}
	return map[string]*Tool{
		"deploy_agent": mk("deploy_agent",
			"Push-install the AI-RMM agent from THIS (source) machine to other Windows computers over SMB (ADMIN$) + remote service control, the same mechanism as PsExec. Uses a Windows credential from the server vault (by name; the AI never sees the password) that is local admin on the targets. The server mints a single-use enrollment token per computer. Targets need TCP 445 reachable from the source and File and Printer Sharing allowed. Use dry_run to check reachability/admin access first.",
			protocol.RiskHigh, 1800, `{"type":"object","properties":{
				"computers":{"type":"array","items":{"type":"string"},"description":"Hostnames or FQDNs (max 25 per job)"},
				"credential":{"type":"string","description":"Name of a 'windows' credential in the vault"},
				"groups":{"type":"array","items":{"type":"string"},"description":"Groups the new agents enroll into (e.g. ot, plant1)"},
				"dry_run":{"type":"boolean","description":"Only test connectivity and admin rights. Default false"},
				"force":{"type":"boolean","description":"Reinstall even if the agent service already exists. Default false"}
			},"required":["computers","credential"]}`),
		"network_scan": mk("network_scan",
			"Discover devices on a subnet from this machine: ping sweep, TCP port probe, reverse DNS and (with an SNMP credential) sysName/sysDescr, to find switches, APs, firewalls, printers, UPSs and unmanaged PCs. CAUTION: active scanning can upset fragile OT/PLC equipment; avoid production-control subnets unless approved.",
			protocol.RiskChange, 900, `{"type":"object","properties":{
				"cidr":{"type":"string","description":"IPv4 subnet, e.g. 10.10.20.0/24 (max /22)"},
				"ports":{"type":"array","items":{"type":"integer"},"description":"TCP ports to probe. Default 22,23,80,443,445,3389,8080,8443,9100"},
				"ping":{"type":"boolean","description":"Default true"},
				"snmp_credential":{"type":"string","description":"Optional 'snmp' vault credential for identification"},
				"timeout_ms":{"type":"integer","minimum":100,"maximum":5000,"description":"Per-probe timeout, default 800"}
			},"required":["cidr"]}`),
	}
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

type deployParams struct {
	Computers  []string `json:"computers"`
	Credential string   `json:"credential"`
	Groups     []string `json:"groups"`
	DryRun     bool     `json:"dry_run"`
	Force      bool     `json:"force"`
}

type scanParams struct {
	CIDR           string `json:"cidr"`
	SNMPCredential string `json:"snmp_credential"`
}

// submitHooks validate native-tool parameters beyond the JSON schema.
var submitHooks = map[string]func(s *Server, params json.RawMessage) error{
	"deploy_agent": func(s *Server, raw json.RawMessage) error {
		var p deployParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if len(p.Computers) == 0 || len(p.Computers) > 25 {
			return errors.New("computers: give 1-25 names per job (split larger rollouts into batches)")
		}
		for _, c := range p.Computers {
			if !hostRe.MatchString(c) {
				return fmt.Errorf("invalid computer name %q", c)
			}
		}
		if _, err := normGroups(p.Groups); err != nil {
			return err
		}
		s.store.mu.Lock()
		_, err := s.credentialLocked(p.Credential, CredWindows)
		s.store.mu.Unlock()
		return err
	},
	"network_scan": func(s *Server, raw json.RawMessage) error {
		var p scanParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		_, n, err := net.ParseCIDR(p.CIDR)
		if err != nil || n.IP.To4() == nil {
			return errors.New("cidr must be an IPv4 subnet like 10.0.0.0/24")
		}
		if ones, _ := n.Mask.Size(); ones < 22 {
			return errors.New("subnet too large: max /22 (1024 addresses) per scan")
		}
		if p.SNMPCredential != "" {
			s.store.mu.Lock()
			_, err := s.credentialLocked(p.SNMPCredential, CredSNMP)
			s.store.mu.Unlock()
			return err
		}
		return nil
	},
}

// dispatchHooks run under store.mu when a job is handed to its agent. They
// return secrets for the signed job and optionally replacement params.
var dispatchHooks = map[string]func(s *Server, j *JobRecord) (map[string]string, json.RawMessage, error){
	"deploy_agent": func(s *Server, j *JobRecord) (map[string]string, json.RawMessage, error) {
		var p deployParams
		if err := json.Unmarshal(j.Params, &p); err != nil {
			return nil, nil, err
		}
		cred, err := s.credentialLocked(p.Credential, CredWindows)
		if err != nil {
			return nil, nil, err
		}
		sec := map[string]string{"username": cred["username"], "password": cred["password"]}
		groups, _ := normGroups(p.Groups)
		if !p.DryRun {
			for _, c := range p.Computers {
				// Single-use, short-lived token per target: nothing reusable
				// ever crosses the network.
				tok := "et_" + randomHex(20)
				t := &EnrollToken{ID: newID("t"), Name: "deploy:" + j.ID + ":" + strings.ToUpper(c), Hash: hashSecret(tok),
					Groups: groups, MaxUses: 1, CreatedAt: now(), ExpiresAt: now() + 3*3600}
				s.store.st.EnrollTokens[t.ID] = t
				sec["token:"+strings.ToUpper(c)] = tok
			}
		}
		// Tell the source agent which signed build to use as the installer.
		var m map[string]interface{}
		_ = json.Unmarshal(j.Params, &m)
		if rel := s.bootstrapReleaseLocked(); rel != nil {
			m["_bootstrap"] = map[string]string{"url": "/api/v1/agent/release/" + rel.File, "sha256": rel.SHA256, "arch": rel.Arch, "variant": rel.Variant}
		}
		extra, _ := json.Marshal(m)
		return sec, extra, nil
	},
	"network_scan": func(s *Server, j *JobRecord) (map[string]string, json.RawMessage, error) {
		var p scanParams
		if err := json.Unmarshal(j.Params, &p); err != nil || p.SNMPCredential == "" {
			return nil, nil, err
		}
		cred, err := s.credentialLocked(p.SNMPCredential, CredSNMP)
		if err != nil {
			return nil, nil, err
		}
		sec := map[string]string{}
		for k, v := range cred {
			sec["snmp_"+k] = v
		}
		return sec, nil, nil
	},
}

// bootstrapReleaseLocked picks the most portable published build to push to
// unknown machines: the 32-bit legacy build runs on every supported Windows
// (7 SP1 .. 11, x86/x64, and ARM64 via emulation). Once enrolled, the server
// cross-grades the agent to the ideal build for its OS.
func (s *Server) bootstrapReleaseLocked() *Release {
	prefs := []struct{ arch, variant string }{{"386", "legacy"}, {"386", ""}, {"amd64", "legacy"}, {"amd64", ""}}
	for _, p := range prefs {
		var best *Release
		for _, r := range s.store.st.Releases {
			if r.OS == "windows" && r.Arch == p.arch && r.Variant == p.variant && len(r.Groups) == 0 && (best == nil || r.CreatedAt > best.CreatedAt) {
				best = r
			}
		}
		if best != nil {
			return best
		}
	}
	return nil
}

// credentialParamHook delivers vault credentials referenced by a custom
// tool's credential_params as "<param>.<field>" secrets.
func credentialParamHook(s *Server, j *JobRecord) (map[string]string, json.RawMessage, error) {
	var pm map[string]interface{}
	_ = json.Unmarshal(j.Params, &pm)
	sec := map[string]string{}
	for _, cp := range j.CredentialParams {
		name, _ := pm[cp].(string)
		if name == "" {
			continue
		}
		cred, err := s.credentialLocked(name, "")
		if err != nil {
			return nil, nil, err
		}
		for k, v := range cred {
			sec[cp+"."+k] = v
		}
	}
	return sec, nil, nil
}
