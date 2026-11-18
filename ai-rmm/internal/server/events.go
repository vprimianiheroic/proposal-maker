package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Event is a notable state change: agent offline/online, device down/up,
// approval needed, schedule fired. Kept in state (bounded) for the AI and
// console, and pushed to alert webhooks.
type Event struct {
	ID       string      `json:"id"`
	Time     int64       `json:"time"`
	Type     string      `json:"type"`
	Severity string      `json:"severity"` // info | warning | critical
	Subject  string      `json:"subject"`  // hostname, device name, batch id
	Text     string      `json:"text"`
	Data     interface{} `json:"data,omitempty"`
}

const maxEvents = 2000

var serverStarted = time.Now()

func (s *Server) emit(typ, severity, subject, text string, data interface{}) {
	e := &Event{ID: newID("e"), Time: now(), Type: typ, Severity: severity, Subject: subject, Text: text, Data: data}
	s.store.mu.Lock()
	s.store.st.Events = append(s.store.st.Events, e)
	if len(s.store.st.Events) > maxEvents {
		s.store.st.Events = s.store.st.Events[len(s.store.st.Events)-maxEvents:]
	}
	s.store.markDirty()
	s.store.mu.Unlock()
	if len(s.Cfg.AlertWebhooks) > 0 {
		go s.sendWebhooks(e)
	}
}

func (s *Server) sendWebhooks(e *Event) {
	icon := map[string]string{"critical": "🔴", "warning": "🟠", "info": "🟢"}[e.Severity]
	body, _ := json.Marshal(map[string]interface{}{
		"text":  fmt.Sprintf("%s [AI-RMM] %s", icon, e.Text),
		"event": e,
	})
	for _, url := range s.Cfg.AlertWebhooks {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			var resp *http.Response
			if resp, err = http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
				if resp.StatusCode >= 300 {
					err = fmt.Errorf("HTTP %d", resp.StatusCode)
				}
			}
		}
		if err != nil {
			log.Printf("alert webhook failed: %v", err)
		}
		cancel()
	}
}

// ListEvents returns events newest first, optionally only since a time / of a type.
func (s *Server) ListEvents(since int64, typ string, limit int) []*Event {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	if limit <= 0 || limit > maxEvents {
		limit = 100
	}
	out := []*Event{}
	for i := len(s.store.st.Events) - 1; i >= 0 && len(out) < limit; i-- {
		e := s.store.st.Events[i]
		if e.Time < since || (typ != "" && e.Type != typ) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// checkAgentsOffline raises agent_offline / agent_online once per transition.
func (s *Server) checkAgentsOffline() {
	// After a server restart every agent looks stale until its next poll.
	if time.Since(serverStarted) < time.Duration(2*s.Cfg.OfflineAfterSec)*time.Second {
		return
	}
	type tr struct {
		host, id string
		online   bool
		last     int64
	}
	var changes []tr
	t0 := now()
	s.store.mu.Lock()
	for _, a := range s.store.st.Agents {
		if a.Disabled {
			continue
		}
		online := t0-a.LastSeen < int64(s.Cfg.OfflineAfterSec)
		if !online && !a.OfflineNotified {
			a.OfflineNotified = true
			changes = append(changes, tr{a.Hostname, a.ID, false, a.LastSeen})
		} else if online && a.OfflineNotified {
			a.OfflineNotified = false
			changes = append(changes, tr{a.Hostname, a.ID, true, a.LastSeen})
		}
	}
	if len(changes) > 0 {
		s.store.markDirty()
	}
	s.store.mu.Unlock()
	for _, c := range changes {
		if c.online {
			s.emit("agent_online", "info", c.host, c.host+" is back online", map[string]string{"agent_id": c.id})
		} else {
			s.emit("agent_offline", "warning", c.host, fmt.Sprintf("%s has not checked in since %s", c.host, time.Unix(c.last, 0).Format(time.RFC1123)), map[string]string{"agent_id": c.id})
		}
	}
}
