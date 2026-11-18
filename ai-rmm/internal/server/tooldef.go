package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/airmm/airmm/internal/protocol"
	"github.com/airmm/airmm/tools"
)

// Tool is one snap-in capability. Built-ins ship in the binary; the AI (or an
// admin) can add more at runtime. AI-authored tools start as drafts, and every
// run of a draft requires human approval until an admin publishes it.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Risk        protocol.Risk   `json:"risk"`
	TimeoutSec  int             `json:"timeout_sec"`
	Params      json.RawMessage `json:"params"` // JSON Schema (object)
	Script      string          `json:"script"`
	Source      string          `json:"source"`         // builtin | custom
	Status      string          `json:"status"`         // published | draft
	Kind        string          `json:"kind,omitempty"` // "" = PowerShell, "native" = implemented inside the agent
	// CredentialParams names string params whose values are vault credential
	// names. At dispatch the credential's fields are delivered as secrets
	// "<param>.<field>" (read with Get-RmmSecret); the agent redacts them
	// from all output.
	CredentialParams []string `json:"credential_params,omitempty"`
	Version          int      `json:"version"`
	Author           string   `json:"author,omitempty"`
	UpdatedAt        int64    `json:"updated_at"`
}

const (
	ToolPublished = "published"
	ToolDraft     = "draft"
)

var toolNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)

func (t *Tool) Validate() error {
	if !toolNameRe.MatchString(t.Name) {
		return errors.New("tool name must match ^[a-z][a-z0-9_]{1,62}$")
	}
	if strings.TrimSpace(t.Description) == "" {
		return errors.New("description is required")
	}
	if !t.Risk.Valid() {
		return errors.New("risk must be read, change or high")
	}
	if t.TimeoutSec <= 0 {
		t.TimeoutSec = 120
	}
	if t.TimeoutSec > 4*3600 {
		return errors.New("timeout_sec may not exceed 14400")
	}
	if len(t.Params) == 0 {
		t.Params = json.RawMessage(`{"type":"object","properties":{}}`)
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(t.Params, &schema); err != nil {
		return fmt.Errorf("params must be a JSON Schema object: %w", err)
	}
	if strings.TrimSpace(t.Script) == "" {
		return errors.New("script is required")
	}
	for _, cp := range t.CredentialParams {
		if !strings.Contains(string(t.Params), `"`+cp+`"`) {
			return fmt.Errorf("credential_params: %q is not a declared parameter", cp)
		}
	}
	if len(t.Script) > 256*1024 {
		return errors.New("script too large (256KB max)")
	}
	return nil
}

// ParseToolFile parses the <#RMM-TOOL {json} #> header format.
func ParseToolFile(src string) (*Tool, error) {
	src = strings.TrimPrefix(src, "\uFEFF")
	const open, close = "<#RMM-TOOL", "#>"
	start := strings.Index(src, open)
	if start < 0 {
		return nil, errors.New("missing <#RMM-TOOL header")
	}
	end := strings.Index(src[start:], close)
	if end < 0 {
		return nil, errors.New("unterminated RMM-TOOL header")
	}
	header := src[start+len(open) : start+end]
	var t Tool
	if err := json.Unmarshal([]byte(header), &t); err != nil {
		return nil, fmt.Errorf("header JSON: %w", err)
	}
	t.Script = strings.TrimSpace(src[start+end+len(close):])
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// BuiltinTools loads the embedded library.
func BuiltinTools() (map[string]*Tool, error) {
	out := map[string]*Tool{}
	err := fs.WalkDir(tools.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".ps1") {
			return err
		}
		b, err := tools.FS.ReadFile(path)
		if err != nil {
			return err
		}
		t, err := ParseToolFile(string(b))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, dup := out[t.Name]; dup {
			return fmt.Errorf("%s: duplicate tool name %s", path, t.Name)
		}
		t.Source, t.Status, t.Version = "builtin", ToolPublished, 1
		out[t.Name] = t
		return nil
	})
	return out, err
}

// ValidateParams is a deliberately small JSON-Schema subset check: object
// type, required, property types, enum, min/max for numbers, and no unknown
// properties. It exists to bounce AI mistakes before they reach a machine.
func ValidateParams(schemaRaw json.RawMessage, params json.RawMessage) (json.RawMessage, error) {
	if len(params) == 0 || string(params) == "null" {
		params = json.RawMessage(`{}`)
	}
	var schema struct {
		Properties map[string]map[string]interface{} `json:"properties"`
		Required   []string                          `json:"required"`
	}
	if err := json.Unmarshal(schemaRaw, &schema); err != nil {
		return nil, fmt.Errorf("tool schema invalid: %w", err)
	}
	var p map[string]interface{}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("params must be a JSON object: %w", err)
	}
	for _, r := range schema.Required {
		if _, ok := p[r]; !ok {
			return nil, fmt.Errorf("missing required param %q", r)
		}
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := p[k]
		prop, ok := schema.Properties[k]
		if !ok {
			return nil, fmt.Errorf("unknown param %q", k)
		}
		if v == nil {
			continue
		}
		typ, _ := prop["type"].(string)
		if err := checkType(k, typ, v); err != nil {
			return nil, err
		}
		if enum, ok := prop["enum"].([]interface{}); ok {
			found := false
			for _, e := range enum {
				if fmt.Sprint(e) == fmt.Sprint(v) {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("param %q must be one of %v", k, enum)
			}
		}
		if f, ok := v.(float64); ok {
			if mn, ok := prop["minimum"].(float64); ok && f < mn {
				return nil, fmt.Errorf("param %q must be >= %v", k, mn)
			}
			if mx, ok := prop["maximum"].(float64); ok && f > mx {
				return nil, fmt.Errorf("param %q must be <= %v", k, mx)
			}
		}
	}
	return json.Marshal(p)
}

func checkType(name, typ string, v interface{}) error {
	ok := true
	switch typ {
	case "", "any":
	case "string":
		_, ok = v.(string)
	case "boolean":
		_, ok = v.(bool)
	case "number":
		_, ok = v.(float64)
	case "integer":
		f, isNum := v.(float64)
		ok = isNum && f == float64(int64(f))
	case "array":
		_, ok = v.([]interface{})
	case "object":
		_, ok = v.(map[string]interface{})
	}
	if !ok {
		return fmt.Errorf("param %q must be of type %s", name, typ)
	}
	return nil
}
