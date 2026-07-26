package gen

import (
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"time"

	"github.com/umadura88/sekisho/internal/snmpcodec"
)

// Well-known OIDs used to build synthetic traps, matching the linkDown
// example in HLD §1.1.1 (Figure 1) exactly.
var (
	oidSysUpTime    = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSnmpTrapOID  = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	oidIfIndex      = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 2, 1, 2, 2, 1, 1}
	oidIfAdminStat  = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 2, 1, 2, 2, 1, 7}
	oidIfOperStat   = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}
	oidLinkDownTrap = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	oidLinkUpTrap   = snmpcodec.ObjectIdentifier{1, 3, 6, 1, 6, 3, 1, 1, 5, 4}
)

type deviceInfo struct {
	Name string
	IP   net.IP
}

// Generator builds and sends synthetic SNMP traps for a Scenario. All
// randomness is derived from a seed, so the same scenario + seed always
// produces the same sequence of events (plan.html §5.2).
type Generator struct {
	scenario *Scenario
	rng      *rand.Rand
	devices  []deviceInfo

	// sendFunc is overridable in tests to capture sent payloads instead of
	// opening a real UDP socket.
	sendFunc func(payload []byte) error
}

// NewGenerator builds a Generator over sc, deriving all randomness from
// seed.
func NewGenerator(sc *Scenario, seed string) *Generator {
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	rng := rand.New(rand.NewSource(int64(h.Sum64())))

	devices := make([]deviceInfo, sc.Devices)
	for i := 0; i < sc.Devices; i++ {
		devices[i] = deviceInfo{
			Name: fmt.Sprintf("device-%03d", i+1),
			IP:   net.IPv4(10, byte((i>>16)&0xff), byte((i>>8)&0xff), byte((i&0xff)+1)),
		}
	}
	return &Generator{scenario: sc, rng: rng, devices: devices}
}

func withInstance(base snmpcodec.ObjectIdentifier, instance int) snmpcodec.ObjectIdentifier {
	return base.WithInstance(instance)
}

// buildLinkTrap builds an IF-MIB::linkDown or IF-MIB::linkUp trap for the
// given device/interface, matching HLD Figure 1's varbind shape exactly.
func (g *Generator) buildLinkTrap(dev deviceInfo, ifIndex int, up bool, uptimeTicks uint64) *snmpcodec.Message {
	trapOID := oidLinkDownTrap
	operStatus := int64(2) // down(2)
	if up {
		trapOID = oidLinkUpTrap
		operStatus = 1 // up(1)
	}
	return &snmpcodec.Message{
		Version:   snmpVersionCode(g.scenario.SNMP.Version),
		Community: g.scenario.SNMP.Community,
		PDUType:   snmpcodec.PDUTrapV2,
		RequestID: g.rng.Int31(),
		Varbinds: []snmpcodec.Varbind{
			{Name: oidSysUpTime.Clone(), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: uptimeTicks}},
			{Name: oidSnmpTrapOID.Clone(), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: trapOID.Clone()}},
			{Name: withInstance(oidIfIndex, ifIndex), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: int64(ifIndex)}},
			{Name: withInstance(oidIfAdminStat, ifIndex), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: 1}},
			{Name: withInstance(oidIfOperStat, ifIndex), Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: operStatus}},
		},
	}
}

// buildGenericAlarm builds a "pattern B" (status-varbind) style trap per
// HLD §5.3: a single trap kind whose varbind value carries the severity.
// statusVal follows a small synthetic enum: 1=critical, 2=major, 3=minor,
// 4=cleared.
func (g *Generator) buildGenericAlarm(trapOID snmpcodec.ObjectIdentifier, uptimeTicks uint64, alarmID int, statusVal int64) *snmpcodec.Message {
	alarmObjectIDOid := trapOID.WithInstance(1, alarmID)
	alarmStatusOid := trapOID.WithInstance(2, alarmID)
	return &snmpcodec.Message{
		Version:   snmpVersionCode(g.scenario.SNMP.Version),
		Community: g.scenario.SNMP.Community,
		PDUType:   snmpcodec.PDUTrapV2,
		RequestID: g.rng.Int31(),
		Varbinds: []snmpcodec.Varbind{
			{Name: oidSysUpTime.Clone(), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: uptimeTicks}},
			{Name: oidSnmpTrapOID.Clone(), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: trapOID.Clone()}},
			{Name: alarmObjectIDOid, Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: int64(alarmID)}},
			{Name: alarmStatusOid, Value: snmpcodec.Value{Type: snmpcodec.TypeInteger, Int: statusVal}},
		},
	}
}

func snmpVersionCode(v string) int {
	if v == "v1" {
		return snmpcodec.VersionV1
	}
	return snmpcodec.VersionV2c
}

// RunOptions configures a generator run.
type RunOptions struct {
	// Target is the destination host:port.
	Target string
	// PPS, if > 0, switches to flat-rate load mode: the scenario's own
	// event rates/holds are ignored and linkDown/linkUp traps are emitted
	// at a uniform PPS rate across the device/interface pool. Requires
	// Duration.
	PPS int
	// Duration bounds the run. Required when PPS is set; defaults to 60s
	// in scenario mode if zero.
	Duration time.Duration
}

// RunStats summarizes one generator run.
type RunStats struct {
	Sent    int
	Errors  int
	Elapsed time.Duration
}

// Run sends synthetic traps according to opts until ctx is cancelled or
// the run's duration elapses.
func (g *Generator) Run(ctx context.Context, opts RunOptions) (RunStats, error) {
	send := g.sendFunc
	var conn net.Conn
	if send == nil {
		c, err := net.Dial("udp", opts.Target)
		if err != nil {
			return RunStats{}, fmt.Errorf("gen: dial target %q: %w", opts.Target, err)
		}
		conn = c
		defer conn.Close()
		send = func(payload []byte) error {
			_, err := conn.Write(payload)
			if err != nil {
				// Sustained high-pps bursts can transiently exhaust the
				// local UDP send buffer (observed under -pps 5000 on
				// darwin). A brief retry clears these without materially
				// affecting the pacing DoD (plan.html §5.2/§9).
				time.Sleep(200 * time.Microsecond)
				_, err = conn.Write(payload)
			}
			return err
		}
	}

	if opts.PPS > 0 {
		if opts.Duration <= 0 {
			return RunStats{}, fmt.Errorf("gen: -duration is required in load mode (-pps set)")
		}
		return g.runLoadMode(ctx, send, opts)
	}
	duration := opts.Duration
	if duration <= 0 {
		duration = 60 * time.Second
	}
	return g.runScenarioMode(ctx, send, duration)
}

// runLoadMode emits a flat-rate stream of linkDown traps (alternating
// devices/interfaces deterministically) at exactly opts.PPS packets/sec,
// for opts.Duration.
func (g *Generator) runLoadMode(ctx context.Context, send func([]byte) error, opts RunOptions) (RunStats, error) {
	start := time.Now()
	deadline := start.Add(opts.Duration)
	var stats RunStats
	var uptime uint64

	for i := 0; ; i++ {
		now := time.Now()
		if now.After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			stats.Elapsed = time.Since(start)
			return stats, nil
		default:
		}

		dev := g.devices[i%len(g.devices)]
		ifIndex := (i % g.scenario.InterfacesPerDevice) + 1
		uptime++
		msg := g.buildLinkTrap(dev, ifIndex, i%2 == 1, uptime)
		payload, err := msg.Encode()
		if err != nil {
			return stats, fmt.Errorf("gen: encode trap: %w", err)
		}

		target := start.Add(time.Duration(stats.Sent) * time.Second / time.Duration(opts.PPS))
		sleepUntil(ctx, target)

		if err := send(payload); err != nil {
			stats.Errors++
		} else {
			stats.Sent++
		}
	}

	stats.Elapsed = time.Since(start)
	return stats, nil
}

// pendingClear is a scheduled linkUp, keyed by virtual time offset from the
// start of the run.
type pendingClear struct {
	at      time.Duration
	dev     deviceInfo
	ifIndex int
}

// runScenarioMode is a discrete-event simulation over a virtual clock: it
// jumps directly from one scheduled event to the next rather than polling
// in real time, so the sequence and count of events produced for a given
// (scenario, seed, duration) is independent of real-world scheduling
// jitter — see plan.html §5.2's --seed determinism requirement, and
// TestGenerator_Determinism. Real-time pacing (so a live run's traffic is
// spread out realistically) is layered on top by sleeping until each
// event's virtual time is reached; it never changes what is sent, only
// when it leaves the process.
func (g *Generator) runScenarioMode(ctx context.Context, send func([]byte) error, duration time.Duration) (RunStats, error) {
	wallStart := time.Now()
	var stats RunStats
	var uptime uint64
	alarmID := 0

	sendMsg := func(msg *snmpcodec.Message) {
		uptime++
		payload, err := msg.Encode()
		if err != nil {
			stats.Errors++
			return
		}
		if err := send(payload); err != nil {
			stats.Errors++
			return
		}
		stats.Sent++
	}

	nextFire := make([]time.Duration, len(g.scenario.Events)) // all start at vt=0
	flapDone := make([]int, len(g.scenario.Events))
	var pending []pendingClear

	for {
		select {
		case <-ctx.Done():
			stats.Elapsed = time.Since(wallStart)
			return stats, nil
		default:
		}

		vt := duration // sentinel: nothing left before the deadline
		for i, ev := range g.scenario.Events {
			if ev.Kind == KindFlap && flapDone[i] >= ev.Count {
				continue
			}
			if nextFire[i] < vt {
				vt = nextFire[i]
			}
		}
		for _, p := range pending {
			if p.at < vt {
				vt = p.at
			}
		}
		if vt >= duration {
			break
		}

		sleepUntil(ctx, wallStart.Add(vt))

		var stillPending []pendingClear
		for _, p := range pending {
			if p.at <= vt {
				sendMsg(g.buildLinkTrap(p.dev, p.ifIndex, true, uptime))
			} else {
				stillPending = append(stillPending, p)
			}
		}
		pending = stillPending

		for i, ev := range g.scenario.Events {
			if nextFire[i] > vt {
				continue
			}
			switch ev.Kind {
			case KindLinkDownUp:
				dev := g.devices[g.rng.Intn(len(g.devices))]
				ifIndex := g.rng.Intn(g.scenario.InterfacesPerDevice) + 1
				sendMsg(g.buildLinkTrap(dev, ifIndex, false, uptime))
				holdSpan := ev.Hold.Max.Std() - ev.Hold.Min.Std() + 1
				hold := ev.Hold.Min.Std() + time.Duration(g.rng.Int63n(int64(holdSpan)))
				pending = append(pending, pendingClear{at: vt + hold, dev: dev, ifIndex: ifIndex})
				nextFire[i] = vt + time.Duration(float64(time.Minute)/ev.RatePerMin)

			case KindFlap:
				if flapDone[i] >= ev.Count {
					continue
				}
				for d := 0; d < ev.Devices && d < len(g.devices); d++ {
					up := flapDone[i]%2 == 1
					sendMsg(g.buildLinkTrap(g.devices[d], 1, up, uptime))
				}
				flapDone[i]++
				nextFire[i] = vt + ev.Interval.Std()

			case KindGenericAlarm:
				trapOID, err := snmpcodec.ParseOID(ev.TrapOID)
				if err != nil {
					stats.Errors++
					nextFire[i] = vt + time.Duration(float64(time.Minute)/ev.RatePerMin)
					continue
				}
				alarmID++
				status := int64(g.rng.Intn(4) + 1) // 1..4
				sendMsg(g.buildGenericAlarm(trapOID, uptime, alarmID, status))
				nextFire[i] = vt + time.Duration(float64(time.Minute)/ev.RatePerMin)
			}
		}
	}

	stats.Elapsed = time.Since(wallStart)
	return stats, nil
}

func sleepUntil(ctx context.Context, t time.Time) {
	d := time.Until(t)
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
