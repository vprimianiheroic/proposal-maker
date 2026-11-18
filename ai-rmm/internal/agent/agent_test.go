package agent

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

func TestCheckDeviceTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	r := checkDevice(context.Background(), protocol.MonitorTarget{ID: "d1", Address: "127.0.0.1", TCPPorts: []int{port}}, 0)
	if !r.Up || !r.Ports[port] {
		t.Fatalf("open port should be up: %+v", r)
	}
	l.Close()
	r = checkDevice(context.Background(), protocol.MonitorTarget{ID: "d1", Address: "127.0.0.1", TCPPorts: []int{port}}, 0)
	if r.Up || !strings.Contains(r.Error, "closed") {
		t.Fatalf("closed port should be down: %+v", r)
	}
}

func TestRedactResult(t *testing.T) {
	res := &protocol.JobResult{Stdout: "pw is Hunter2!x", Stderr: "", Data: json.RawMessage(`{"a":"Hunter2!x","b":"q\"uote-secret"}`)}
	redactResult(res, map[string]string{"p": "Hunter2!x", "q": `q"uote-secret`, "short": "ab"})
	all := res.Stdout + string(res.Data)
	if strings.Contains(all, "Hunter2") || strings.Contains(all, "uote-secret") || !json.Valid(res.Data) {
		t.Fatalf("not redacted: %s / %s", res.Stdout, res.Data)
	}
}

func TestExpandCIDR(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/30", 1024)
	if err != nil || len(ips) != 2 || ips[0] != "192.168.1.1" || ips[1] != "192.168.1.2" {
		t.Fatalf("%v %v", ips, err)
	}
	if _, err := expandCIDR("10.0.0.0/16", 1024); err == nil {
		t.Fatal("too large accepted")
	}
}

func TestGuessKind(t *testing.T) {
	cases := map[string]scanHost{
		"switch":   {SysDescr: "Cisco IOS Software, C2960X Software"},
		"firewall": {SysDescr: "FortiGate-60F v7.2"},
		"printer":  {OpenPorts: []int{80, 9100}},
		"ups":      {SysDescr: "APC Web/SNMP Management Card"},
		"windows":  {OpenPorts: []int{445, 3389}},
	}
	for want, h := range cases {
		if got := guessKind(h); got != want {
			t.Errorf("%+v: got %s want %s", h, got, want)
		}
	}
}

func TestEndpointsKeepInstallURL(t *testing.T) {
	c := &Config{ServerURL: "https://new:8443", ServerURLs: []string{"https://10.0.0.5:8443", "https://new:8443/"}, InstallURL: "https://old:8443"}
	got := strings.Join(c.Endpoints(), ",")
	if got != "https://new:8443,https://10.0.0.5:8443,https://old:8443" {
		t.Fatal(got)
	}
}

func TestUpdateMarkerStampedOnce(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/" + updateMarker
	if err := os.WriteFile(p, []byte(`{"from":"1","to":"2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanupOldBinary(dir)
	b1, _ := os.ReadFile(p)
	time.Sleep(1100 * time.Millisecond)
	cleanupOldBinary(dir) // crash-loop restart must not reset the clock
	b2, _ := os.ReadFile(p)
	if string(b1) != string(b2) || !strings.Contains(string(b1), "started_at") {
		t.Fatalf("marker restamped: %s vs %s", b1, b2)
	}
	if age, ok := markerAge(p); !ok || age < time.Second {
		t.Fatalf("age %v", age)
	}
}
