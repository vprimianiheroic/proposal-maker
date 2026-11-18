package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Schedule runs a tool on targets at a recurring time, e.g. "install
// security updates on group:office every Wednesday 02:00, window 3h".
//
// Approval model: a human approves the *schedule* (tool + exact params +
// targets + timing) once; its runs are then pre-approved. Any change by a
// non-admin un-approves it, and if the tool's code changes after approval
// (new version or back to draft) runs fall back to normal approval.
type Schedule struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Tool          string          `json:"tool"`
	ToolVersion   int             `json:"tool_version"`
	Targets       []string        `json:"targets"`
	Params        json.RawMessage `json:"params"`
	Reason        string          `json:"reason"`
	Days          []string        `json:"days"` // mon..sun; empty = every day
	Time          string          `json:"time"` // HH:MM, server timezone
	WindowMinutes int             `json:"window_minutes"`
	Enabled       bool            `json:"enabled"`
	Approved      bool            `json:"approved"`
	CreatedBy     string          `json:"created_by"`
	ApprovedBy    string          `json:"approved_by,omitempty"`
	UpdatedAt     int64           `json:"updated_at"`
	LastRun       int64           `json:"last_run,omitempty"`
	LastBatch     string          `json:"last_batch,omitempty"`
	NextRun       int64           `json:"next_run,omitempty"`
}

const RoleSchedule = "schedule"

var weekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

func (s *Server) location() *time.Location {
	if s.Cfg.Timezone != "" {
		if loc, err := time.LoadLocation(s.Cfg.Timezone); err == nil {
			return loc
		}
	}
	return time.Local
}

// nextRun returns the first occurrence strictly after t.
func (sc *Schedule) nextRun(t time.Time, loc *time.Location) (time.Time, error) {
	var hh, mm int
	if _, err := fmt.Sscanf(sc.Time, "%d:%d", &hh, &mm); err != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return time.Time{}, errors.New("time must be HH:MM (24h)")
	}
	days := map[time.Weekday]bool{}
	for _, d := range sc.Days {
		wd, ok := weekdays[strings.ToLower(strings.TrimSpace(d))[:min3(d)]]
		if !ok {
			return time.Time{}, fmt.Errorf("unknown day %q (use mon..sun)", d)
		}
		days[wd] = true
	}
	lt := t.In(loc)
	for i := 0; i <= 8; i++ {
		d := lt.AddDate(0, 0, i)
		cand := time.Date(d.Year(), d.Month(), d.Day(), hh, mm, 0, 0, loc)
		if cand.After(t) && (len(days) == 0 || days[cand.Weekday()]) {
			return cand, nil
		}
	}
	return time.Time{}, errors.New("no next run found")
}

func min3(d string) int {
	if n := len(strings.TrimSpace(d)); n < 3 {
		return n
	}
	return 3
}

func (s *Server) SaveSchedule(c Caller, sc *Schedule) (*Schedule, error) {
	if strings.TrimSpace(sc.Name) == "" || strings.TrimSpace(sc.Reason) == "" {
		return nil, errors.New("name and reason are required")
	}
	t, ok := s.LookupTool(sc.Tool)
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", sc.Tool)
	}
	p, err := ValidateParams(t.Params, sc.Params)
	if err != nil {
		return nil, err
	}
	sc.Params = p
	if len(sc.Targets) == 0 {
		return nil, errors.New("targets required")
	}
	if sc.WindowMinutes <= 0 {
		sc.WindowMinutes = 120
	}
	if sc.WindowMinutes > 24*60 {
		sc.WindowMinutes = 24 * 60
	}
	next, err := sc.nextRun(time.Now(), s.location())
	if err != nil {
		return nil, err
	}
	sc.NextRun = next.Unix()
	sc.ToolVersion = t.Version
	sc.UpdatedAt = now()
	s.store.mu.Lock()
	if sc.ID == "" {
		sc.ID = newID("s")
		sc.CreatedBy = c.String()
	} else if old, ok := s.store.st.Schedules[sc.ID]; ok {
		sc.CreatedBy, sc.LastRun, sc.LastBatch = old.CreatedBy, old.LastRun, old.LastBatch
	} else {
		s.store.mu.Unlock()
		return nil, errors.New("no such schedule")
	}
	sc.Approved, sc.ApprovedBy = false, ""
	if c.Role == RoleAdmin {
		sc.Approved, sc.ApprovedBy = true, c.String()
	}
	s.store.st.Schedules[sc.ID] = sc
	s.store.markDirty()
	cp := *sc
	s.store.mu.Unlock()
	s.Audit(c.String(), "schedule.save", sc)
	if !cp.Approved {
		s.emit("approval_needed", "info", cp.Name, fmt.Sprintf("Schedule %q (%s on %s) by %s needs approval", cp.Name, cp.Tool, strings.Join(cp.Targets, ","), cp.CreatedBy), map[string]string{"schedule_id": cp.ID})
	}
	return &cp, nil
}

func (s *Server) ApproveSchedule(c Caller, id string) error {
	if c.Role != RoleAdmin {
		return errors.New("only an admin can approve schedules")
	}
	s.store.mu.Lock()
	sc, ok := s.store.st.Schedules[id]
	if ok {
		if t, tok := s.lookupToolLocked(sc.Tool); tok {
			sc.ToolVersion = t.Version
		}
		sc.Approved, sc.ApprovedBy = true, c.String()
		s.store.markDirty()
	}
	s.store.mu.Unlock()
	if !ok {
		return errors.New("no such schedule")
	}
	s.Audit(c.String(), "schedule.approve", map[string]string{"id": id})
	return nil
}

// SetScheduleEnabled lets anyone pause a schedule; re-enabling keeps the
// existing approval state (an unapproved schedule still won't run).
func (s *Server) SetScheduleEnabled(c Caller, id string, enabled bool) error {
	s.store.mu.Lock()
	sc, ok := s.store.st.Schedules[id]
	if ok {
		sc.Enabled = enabled
		if n, err := sc.nextRun(time.Now(), s.location()); err == nil {
			sc.NextRun = n.Unix()
		}
		s.store.markDirty()
	}
	s.store.mu.Unlock()
	if !ok {
		return errors.New("no such schedule")
	}
	s.Audit(c.String(), "schedule.enable", map[string]interface{}{"id": id, "enabled": enabled})
	return nil
}

func (s *Server) DeleteSchedule(c Caller, id string) error {
	s.store.mu.Lock()
	_, ok := s.store.st.Schedules[id]
	delete(s.store.st.Schedules, id)
	s.store.markDirty()
	s.store.mu.Unlock()
	if !ok {
		return errors.New("no such schedule")
	}
	s.Audit(c.String(), "schedule.delete", map[string]string{"id": id})
	return nil
}

func (s *Server) ListSchedules() []*Schedule {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	out := []*Schedule{}
	for _, sc := range s.store.st.Schedules {
		c := *sc
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextRun < out[j].NextRun })
	return out
}

// runDueSchedules is called from the background loop.
func (s *Server) runDueSchedules() {
	t := time.Now()
	loc := s.location()
	type due struct {
		sc     Schedule
		missed bool
	}
	var todo []due
	s.store.mu.Lock()
	for _, sc := range s.store.st.Schedules {
		if !sc.Enabled || sc.NextRun == 0 || t.Unix() < sc.NextRun {
			continue
		}
		// Server was down past the whole window: skip this occurrence.
		missed := t.Unix() > sc.NextRun+int64(sc.WindowMinutes*60)
		if sc.Approved {
			todo = append(todo, due{*sc, missed})
		}
		if n, err := sc.nextRun(t, loc); err == nil {
			sc.NextRun = n.Unix()
		}
		s.store.markDirty()
	}
	s.store.mu.Unlock()

	for _, d := range todo {
		sc := d.sc
		if d.missed {
			s.emit("schedule_missed", "warning", sc.Name, fmt.Sprintf("Schedule %q missed its window (server was unavailable)", sc.Name), nil)
			continue
		}
		caller := Caller{Name: sc.Name, Role: RoleSchedule}
		reason := fmt.Sprintf("[schedule %s, approved by %s] %s", sc.Name, sc.ApprovedBy, sc.Reason)
		if t, ok := s.LookupTool(sc.Tool); !ok || t.Version != sc.ToolVersion || t.Status != ToolPublished {
			// The code behind the approved schedule changed: require approval again.
			caller.Role = RoleAI
			reason += " (tool changed since the schedule was approved)"
		}
		elapsed := int(time.Now().Unix()-sc.NextRun) / 60
		queue := sc.WindowMinutes - elapsed
		if queue < 5 {
			queue = 5
		}
		res, err := s.Submit(caller, SubmitRequest{Tool: sc.Tool, Targets: sc.Targets, Params: sc.Params, Reason: reason, QueueMin: queue})
		s.store.mu.Lock()
		if cur, ok := s.store.st.Schedules[sc.ID]; ok {
			cur.LastRun = now()
			if res != nil {
				cur.LastBatch = res.BatchID
			}
			s.store.markDirty()
		}
		s.store.mu.Unlock()
		if err != nil {
			s.emit("schedule_failed", "warning", sc.Name, fmt.Sprintf("Schedule %q could not start: %v", sc.Name, err), nil)
		} else {
			s.emit("schedule_ran", "info", sc.Name, fmt.Sprintf("Schedule %q started %s on %d machine(s)", sc.Name, sc.Tool, len(res.Jobs)), map[string]string{"batch_id": res.BatchID})
		}
	}
}
