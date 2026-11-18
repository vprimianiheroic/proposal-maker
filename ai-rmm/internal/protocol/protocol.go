// Package protocol holds the wire types shared by the server and the agent,
// plus the Ed25519 signing scheme that lets an agent refuse any job the
// server's signing key did not authorise.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Risk classifies what a tool can do to a machine. Policy decides, per agent
// group, which risk levels an AI caller may run without a human approving.
type Risk string

const (
	RiskRead   Risk = "read"   // observes only
	RiskChange Risk = "change" // reversible, low-blast-radius changes (restart a service, flush DNS)
	RiskHigh   Risk = "high"   // reboots, installs, AD account changes, arbitrary scripts
	RiskNone   Risk = "none"   // policy value only: nothing auto-approves
)

// Level returns an ordinal for comparison; unknown values rank highest so
// they always require approval.
func (r Risk) Level() int {
	switch r {
	case RiskNone:
		return 0
	case RiskRead:
		return 1
	case RiskChange:
		return 2
	case RiskHigh:
		return 3
	}
	return 99
}

func (r Risk) Valid() bool { return r == RiskRead || r == RiskChange || r == RiskHigh }

// Job is what the server hands an agent to execute. Every field that affects
// execution is covered by Signature.
type Job struct {
	ID      string          `json:"id"`
	AgentID string          `json:"agent_id"`
	Tool    string          `json:"tool"`
	Kind    string          `json:"kind,omitempty"` // "" = PowerShell script, "native" = built into the agent
	Script  string          `json:"script"`         // PowerShell body
	Params  json.RawMessage `json:"params"`
	// Secrets are injected by the server at dispatch (vault credentials,
	// single-use enrollment tokens). They are never stored with the job and
	// are exposed to scripts only through Get-RmmSecret.
	Secrets    map[string]string `json:"secrets,omitempty"`
	TimeoutSec int               `json:"timeout_sec"`
	IssuedAt   int64             `json:"issued_at"`  // unix seconds
	ExpiresAt  int64             `json:"expires_at"` // unix seconds; agent refuses after this
	Signature  string            `json:"signature"`  // base64 Ed25519 over SigningBytes()
}

// SigningBytes is a length-prefixed canonical encoding (not JSON, so map
// ordering and whitespace can never make two encodings of one job differ).
func (j *Job) SigningBytes() []byte {
	var b bytes.Buffer
	b.WriteString("airmm-job-v2")
	for _, f := range []string{j.ID, j.AgentID, j.Tool, j.Kind, j.Script, string(j.Params)} {
		writeField(&b, []byte(f))
	}
	keys := make([]string, 0, len(j.Secrets))
	for k := range j.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeField(&b, []byte(fmt.Sprint(len(keys))))
	for _, k := range keys {
		writeField(&b, []byte(k))
		writeField(&b, []byte(j.Secrets[k]))
	}
	var n [8]byte
	for _, v := range []int64{int64(j.TimeoutSec), j.IssuedAt, j.ExpiresAt} {
		binary.BigEndian.PutUint64(n[:], uint64(v))
		b.Write(n[:])
	}
	return b.Bytes()
}

func writeField(b *bytes.Buffer, f []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(f)))
	b.Write(n[:])
	b.Write(f)
}

func (j *Job) Sign(key ed25519.PrivateKey) {
	j.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, j.SigningBytes()))
}

// Verify checks signature, intended recipient and expiry.
func (j *Job) Verify(pub ed25519.PublicKey, agentID string, now time.Time) error {
	sig, err := base64.StdEncoding.DecodeString(j.Signature)
	if err != nil {
		return fmt.Errorf("bad signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, j.SigningBytes(), sig) {
		return errors.New("signature verification failed")
	}
	if j.AgentID != agentID {
		return fmt.Errorf("job addressed to %s, not this agent", j.AgentID)
	}
	if now.Unix() > j.ExpiresAt {
		return errors.New("job expired")
	}
	if j.TimeoutSec <= 0 || j.TimeoutSec > 24*3600 {
		return errors.New("invalid timeout")
	}
	return nil
}

// UpdateInfo tells an agent a different build is assigned to it.
type UpdateInfo struct {
	Version   string `json:"version"`
	Arch      string `json:"arch"`    // may differ from the running build (cross-grade, e.g. 386 -> amd64)
	Variant   string `json:"variant"` // "" or "legacy"
	URL       string `json:"url"`     // relative to server URL
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"` // over UpdateSigningBytes
}

func UpdateSigningBytes(osName, arch, variant, version, sha string) []byte {
	return []byte(strings.Join([]string{"airmm-update-v1", osName, arch, variant, version, strings.ToLower(sha)}, "|"))
}

// Facts is the cheap, natively collected inventory sent with heartbeats.
// Anything deeper is a tool.
type Facts struct {
	Hostname     string   `json:"hostname"`
	Domain       string   `json:"domain,omitempty"`
	DomainJoined bool     `json:"domain_joined"`
	OSName       string   `json:"os_name"`
	OSVersion    string   `json:"os_version"` // e.g. 10.0.19045
	OSBuild      string   `json:"os_build,omitempty"`
	ProductType  string   `json:"product_type,omitempty"` // workstation | domain_controller | server
	Arch         string   `json:"arch"`                   // agent binary architecture (selects update builds)
	OSArch       string   `json:"os_arch"`                // OS architecture
	IPs          []string `json:"ips,omitempty"`
	MACs         []string `json:"macs,omitempty"`
	BootTime     int64    `json:"boot_time,omitempty"`
	CPUs         int      `json:"cpus"`
	PSVersion    string   `json:"ps_version,omitempty"`
}

type EnrollRequest struct {
	Token        string `json:"token"`
	AgentVersion string `json:"agent_version"`
	Variant      string `json:"variant"`
	Facts        Facts  `json:"facts"`
}

type EnrollResponse struct {
	AgentID string `json:"agent_id"`
	Secret  string `json:"secret"`
}

type PollRequest struct {
	AgentVersion   string   `json:"agent_version"`
	Variant        string   `json:"variant"`
	MonitorVersion string   `json:"monitor_version,omitempty"`
	Facts          *Facts   `json:"facts,omitempty"` // sent on start and periodically
	Running        []string `json:"running,omitempty"`
}

type PollResponse struct {
	Jobs   []Job       `json:"jobs,omitempty"`
	Update *UpdateInfo `json:"update,omitempty"`
	// ServerURLs, when set, replaces the agent's ordered list of server
	// addresses (primary first). Lets the server be moved without losing agents.
	ServerURLs []string `json:"server_urls,omitempty"`
	// Monitor is sent when the agent's monitoring assignment changed.
	Monitor *MonitorConfig `json:"monitor,omitempty"`
}

// ---- network monitoring (agents act as collectors) ----

type MonitorConfig struct {
	Version string          `json:"version"`
	Devices []MonitorTarget `json:"devices"`
}

type MonitorTarget struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Address     string    `json:"address"`
	IntervalSec int       `json:"interval_sec"`
	Ping        bool      `json:"ping"`
	TCPPorts    []int     `json:"tcp_ports,omitempty"`
	SNMP        *SNMPAuth `json:"snmp,omitempty"`
}

// SNMPAuth comes from the server's credential vault.
type SNMPAuth struct {
	Version   string `json:"version"` // "2c" | "3"
	Community string `json:"community,omitempty"`
	Username  string `json:"username,omitempty"`
	AuthProto string `json:"auth_proto,omitempty"` // MD5 | SHA | SHA256 | SHA512
	AuthPass  string `json:"auth_pass,omitempty"`
	PrivProto string `json:"priv_proto,omitempty"` // DES | AES | AES256
	PrivPass  string `json:"priv_pass,omitempty"`
	Port      int    `json:"port,omitempty"`
}

type MonitorReport struct {
	DeviceID  string        `json:"device_id"`
	Time      int64         `json:"time"`
	Up        bool          `json:"up"`
	LatencyMs float64       `json:"latency_ms,omitempty"`
	PingOK    *bool         `json:"ping_ok,omitempty"`
	Ports     map[int]bool  `json:"ports,omitempty"`
	SNMP      *SNMPSnapshot `json:"snmp,omitempty"`
	Error     string        `json:"error,omitempty"`
}

type SNMPSnapshot struct {
	OK         bool        `json:"ok"`
	SysName    string      `json:"sys_name,omitempty"`
	SysDescr   string      `json:"sys_descr,omitempty"`
	SysUptimeS int64       `json:"sys_uptime_sec,omitempty"`
	Location   string      `json:"location,omitempty"`
	Contact    string      `json:"contact,omitempty"`
	Interfaces []Interface `json:"interfaces,omitempty"` // present on interface-walk cycles only
	Error      string      `json:"error,omitempty"`
}

type Interface struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	Alias     string `json:"alias,omitempty"`
	AdminUp   bool   `json:"admin_up"`
	OperUp    bool   `json:"oper_up"`
	SpeedMbps uint64 `json:"speed_mbps,omitempty"`
	InErrors  uint64 `json:"in_errors,omitempty"`
	OutErrors uint64 `json:"out_errors,omitempty"`
	InOctets  uint64 `json:"in_octets,omitempty"`
	OutOctets uint64 `json:"out_octets,omitempty"`
}

// Job status values.
const (
	StatusPendingApproval = "pending_approval"
	StatusQueued          = "queued"
	StatusDispatched      = "dispatched"
	StatusSucceeded       = "succeeded"
	StatusFailed          = "failed"
	StatusTimeout         = "timeout"
	StatusRejected        = "rejected" // agent refused (bad signature, expired...)
	StatusDenied          = "denied"   // human denied approval
	StatusExpired         = "expired"  // agent never picked it up in time
	StatusCancelled       = "cancelled"
)

func IsTerminal(s string) bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusTimeout, StatusRejected, StatusDenied, StatusExpired, StatusCancelled:
		return true
	}
	return false
}

type JobResult struct {
	JobID      string          `json:"job_id"`
	Status     string          `json:"status"`
	ExitCode   int             `json:"exit_code"`
	Stdout     string          `json:"stdout,omitempty"`
	Stderr     string          `json:"stderr,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"` // structured output of the tool
	StartedAt  int64           `json:"started_at"`
	FinishedAt int64           `json:"finished_at"`
}

// DataMarker separates human/host noise on stdout from the tool's JSON result.
const DataMarker = "<<<RMM-DATA>>>"
