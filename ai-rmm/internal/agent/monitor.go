package agent

import (
	"context"
	"log"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/airmm/airmm/internal/protocol"
)

// collector runs the network-device checks assigned to this agent and
// batches the results back to the server.
type collector struct {
	a       *Agent
	mu      sync.Mutex
	version string
	loops   map[string]*devLoop
	out     chan protocol.MonitorReport
}

type devLoop struct {
	target protocol.MonitorTarget
	cancel context.CancelFunc
}

func newCollector(a *Agent) *collector {
	return &collector{a: a, loops: map[string]*devLoop{}, out: make(chan protocol.MonitorReport, 1000)}
}

func (c *collector) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// Apply reconciles running checks with a new assignment.
func (c *collector) Apply(ctx context.Context, cfg *protocol.MonitorConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := map[string]protocol.MonitorTarget{}
	for _, d := range cfg.Devices {
		want[d.ID] = d
	}
	for id, l := range c.loops {
		if t, ok := want[id]; !ok || !reflect.DeepEqual(t, l.target) {
			l.cancel()
			delete(c.loops, id)
		}
	}
	for id, t := range want {
		if _, ok := c.loops[id]; ok {
			continue
		}
		lctx, cancel := context.WithCancel(ctx)
		c.loops[id] = &devLoop{target: t, cancel: cancel}
		go c.run(lctx, t)
	}
	c.version = cfg.Version
	log.Printf("monitoring %d network device(s)", len(c.loops))
}

func (c *collector) run(ctx context.Context, t protocol.MonitorTarget) {
	interval := time.Duration(t.IntervalSec) * time.Second
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	// Spread devices over the interval so a big list doesn't burst.
	if !sleepCtx(ctx, time.Duration(rand.Int63n(int64(interval)))) {
		return
	}
	cycle := 0
	for {
		// Walk the interface table every 5th check (and the first).
		walk := 0
		if cycle%5 == 0 {
			walk = 500
		}
		rep := checkDevice(ctx, t, walk)
		select {
		case c.out <- rep:
		default: // server unreachable for a long time; drop rather than block
		}
		cycle++
		if !sleepCtx(ctx, interval) {
			return
		}
	}
}

func checkDevice(ctx context.Context, t protocol.MonitorTarget, walkIfaces int) protocol.MonitorReport {
	r := protocol.MonitorReport{DeviceID: t.ID, Time: time.Now().Unix()}
	tmo := 2 * time.Second
	var errs []string
	if t.Ping {
		ms, ok := pingOnce(ctx, t.Address, tmo)
		if !ok { // one retry before calling it lost
			ms, ok = pingOnce(ctx, t.Address, tmo)
		}
		r.PingOK = &ok
		if ok {
			r.Up, r.LatencyMs = true, ms
		} else {
			errs = append(errs, "no ping reply")
		}
	}
	if len(t.TCPPorts) > 0 {
		r.Ports = map[int]bool{}
		allOpen := true
		for _, p := range t.TCPPorts {
			start := time.Now()
			open, _ := tcpProbe(ctx, t.Address, p, 3*time.Second)
			r.Ports[p] = open
			if open && r.LatencyMs == 0 {
				r.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
			}
			if !open {
				allOpen = false
				errs = append(errs, "tcp/"+strconv.Itoa(p)+" closed")
			}
		}
		// Explicitly monitored ports are service checks: all must answer.
		r.Up = allOpen && (r.PingOK == nil || *r.PingOK)
	}
	if t.SNMP != nil {
		snap, err := snmpSystem(t.Address, t.SNMP, 3*time.Second, walkIfaces)
		if err != nil {
			r.SNMP = &protocol.SNMPSnapshot{OK: false, Error: err.Error()}
			errs = append(errs, "snmp: "+err.Error())
			if !t.Ping && len(t.TCPPorts) == 0 {
				r.Up = false
			}
		} else {
			r.SNMP = snap
			if !t.Ping && len(t.TCPPorts) == 0 {
				r.Up = true
			}
		}
	}
	if len(errs) > 0 {
		r.Error = strings.Join(errs, "; ")
	}
	return r
}

// sender flushes reports every 15 s.
func (c *collector) sender(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	var buf []protocol.MonitorReport
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-c.out:
			buf = append(buf, r)
			if len(buf) > 2000 {
				buf = buf[len(buf)-2000:]
			}
		case <-tick.C:
			if len(buf) == 0 {
				continue
			}
			sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := c.a.do(sctx, "POST", "/api/v1/agent/monitor", buf, nil, true)
			cancel()
			if err == nil {
				buf = buf[:0]
			}
		}
	}
}
