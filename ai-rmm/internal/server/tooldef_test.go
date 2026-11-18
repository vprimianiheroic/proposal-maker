package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/airmm/airmm/internal/protocol"
)

func TestBuiltinToolsParse(t *testing.T) {
	tools, err := BuiltinTools()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) < 30 {
		t.Fatalf("expected the full library, got %d tools", len(tools))
	}
	for name, tl := range tools {
		if strings.Contains(tl.Script, "<#RMM-TOOL") {
			t.Errorf("%s: header leaked into script", name)
		}
		// Every declared required param must exist in properties.
		var sc struct {
			Properties map[string]interface{} `json:"properties"`
			Required   []string               `json:"required"`
		}
		if err := json.Unmarshal(tl.Params, &sc); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for _, r := range sc.Required {
			if _, ok := sc.Properties[r]; !ok {
				t.Errorf("%s: required param %s not in properties", name, r)
			}
		}
		// Every Get-RmmParam 'x' must be a declared property (catches typos).
		for _, part := range strings.Split(tl.Script, "Get-RmmParam '")[1:] {
			p := part[:strings.IndexByte(part, '\'')]
			if _, ok := sc.Properties[p]; !ok {
				t.Errorf("%s: script reads undeclared param %q", name, p)
			}
		}
	}
	// Spot-check risk classification of dangerous tools.
	for _, n := range []string{"reboot", "install_windows_updates", "install_msi", "registry_set", "ad_set_user_enabled", "uninstall_software"} {
		if tools[n] == nil || tools[n].Risk != protocol.RiskHigh {
			t.Errorf("%s must be high risk", n)
		}
	}
}

func TestValidateParams(t *testing.T) {
	sc := json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer","minimum":1,"maximum":5},"s":{"type":"string","enum":["a","b"]},"b":{"type":"boolean"}},"required":["n"]}`)
	ok := []string{`{"n":3}`, `{"n":1,"s":"a","b":true}`}
	bad := []string{`{}`, `{"n":0}`, `{"n":2.5}`, `{"n":"3"}`, `{"n":3,"s":"c"}`, `{"n":3,"x":1}`, `[1]`}
	for _, o := range ok {
		if _, err := ValidateParams(sc, json.RawMessage(o)); err != nil {
			t.Errorf("%s should pass: %v", o, err)
		}
	}
	for _, b := range bad {
		if _, err := ValidateParams(sc, json.RawMessage(b)); err == nil {
			t.Errorf("%s should fail", b)
		}
	}
}

func TestEffectivePolicyStrictest(t *testing.T) {
	c := DefaultConfig()
	p, _ := c.EffectivePolicy(nil)
	if p.AutoApproveMaxRisk != protocol.RiskChange {
		t.Fatalf("default: %s", p.AutoApproveMaxRisk)
	}
	c.GroupPolicies["lockdown"] = Policy{AutoApproveMaxRisk: protocol.RiskNone}
	c.GroupPolicies["loose"] = Policy{AutoApproveMaxRisk: protocol.RiskHigh, AllowAdHocScripts: true}
	p, src := c.EffectivePolicy([]string{"loose", "lockdown"})
	if p.AutoApproveMaxRisk != protocol.RiskNone || len(src) != 3 {
		t.Fatalf("strictest should win: %+v %v", p, src)
	}
	p, _ = c.EffectivePolicy([]string{"loose"})
	if p.AutoApproveMaxRisk != protocol.RiskChange {
		t.Fatalf("a group must not loosen the default: %s", p.AutoApproveMaxRisk)
	}
}
