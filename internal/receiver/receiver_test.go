package receiver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/umadura88/sekisho/internal/event"
	"github.com/umadura88/sekisho/internal/gen"
	"github.com/umadura88/sekisho/internal/replay"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

func oid(s string) snmpcodec.ObjectIdentifier {
	o, err := snmpcodec.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

// startReceiver launches a single-worker receiver with a deterministic
// clock and sequential IDs, collecting events into a slice.
func startReceiver(t *testing.T) (addr string, events func() []*event.Event, stop func() *Stats) {
	t.Helper()
	var mu sync.Mutex
	var got []*event.Event

	seq := 0
	r := New(Config{
		Bind:    "127.0.0.1:0",
		Workers: 1, // in-order delivery for assertions
		Now:     func() time.Time { return time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC) },
		NewID: func() (string, error) {
			seq++
			return fmt.Sprintf("evt-%04d", seq), nil
		},
	}, func(ev *event.Event) {
		mu.Lock()
		got = append(got, ev)
		mu.Unlock()
	})
	if err := r.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	snapshot := func() []*event.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]*event.Event(nil), got...)
	}
	return r.LocalAddr().String(), snapshot, func() *Stats {
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Run: %v", err)
		}
		return r.Stats()
	}
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}

// TestReceiver_MixedTraffic covers M1a DoD ② and ③ end to end over a real
// socket: a v2c trap and a v1 trap produce normalized events; garbage, a
// non-trap PDU, and a v3 message are counted without crashing and produce
// nothing.
func TestReceiver_MixedTraffic(t *testing.T) {
	addr, events, stop := startReceiver(t)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// 1: valid v2c linkDown
	v2 := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUTrapV2, RequestID: 1,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeTimeTicks, UInt: 10}},
			{Name: oid("1.3.6.1.6.3.1.1.4.1.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeObjectIdentifier, OID: oid("1.3.6.1.6.3.1.1.5.3")}},
		},
	}
	v2b, _ := v2.Encode()
	conn.Write(v2b)

	// 2: valid v1 enterprise-specific trap
	v1 := &snmpcodec.Message{
		Version: snmpcodec.VersionV1, Community: "public",
		PDUType:      snmpcodec.PDUTrapV1,
		Enterprise:   oid("1.3.6.1.4.1.9999"),
		AgentAddr:    net.IPv4(10, 0, 0, 33).To4(),
		GenericTrap:  6,
		SpecificTrap: 42,
		Timestamp:    5,
	}
	v1b, _ := v1.Encode()
	conn.Write(v1b)

	// 3: garbage
	conn.Write([]byte("definitely not BER"))

	// 4: a GetRequest (SNMP, but not a trap)
	get := &snmpcodec.Message{
		Version: snmpcodec.VersionV2c, Community: "public",
		PDUType: snmpcodec.PDUGetRequest, RequestID: 2,
		Varbinds: []snmpcodec.Varbind{
			{Name: oid("1.3.6.1.2.1.1.3.0"), Value: snmpcodec.Value{Type: snmpcodec.TypeNull}},
		},
	}
	getb, _ := get.Encode()
	conn.Write(getb)

	// 5: a v3-looking message
	conn.Write([]byte{0x30, 0x06, 0x02, 0x01, 0x03, 0x04, 0x01, 0x78})

	waitFor(t, func() bool { return len(events()) >= 2 })
	stats := stop()

	if stats.Received.Load() != 5 {
		t.Errorf("Received = %d, want 5", stats.Received.Load())
	}
	if stats.Events.Load() != 2 {
		t.Errorf("Events = %d, want 2", stats.Events.Load())
	}
	if stats.DecodeFailed.Load() != 1 {
		t.Errorf("DecodeFailed = %d, want 1", stats.DecodeFailed.Load())
	}
	if stats.NonTrapPDU.Load() != 1 {
		t.Errorf("NonTrapPDU = %d, want 1", stats.NonTrapPDU.Load())
	}
	if stats.UnsupportedVersion.Load() != 1 {
		t.Errorf("UnsupportedVersion = %d, want 1", stats.UnsupportedVersion.Load())
	}

	evs := events()
	if evs[0].Version != "v2c" || evs[0].TrapOID != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("event 1 = %+v", evs[0])
	}
	if evs[0].EventID != "evt-0001" {
		t.Errorf("event 1 id = %q, want evt-0001", evs[0].EventID)
	}
	// v1 normalization all the way through the socket path (DoD ②).
	if evs[1].Version != "v1" || evs[1].TrapOID != "1.3.6.1.4.1.9999.0.42" {
		t.Errorf("event 2 = %+v", evs[1])
	}
	if evs[1].DeviceID != "10.0.0.33" {
		t.Errorf("event 2 device_id = %q, want agent-addr 10.0.0.33", evs[1].DeviceID)
	}
	if !strings.HasPrefix(evs[1].SourceAddr, "127.0.0.1:") {
		t.Errorf("event 2 source_addr = %q, want the sender socket", evs[1].SourceAddr)
	}

	// The golden JSON shape must serialize cleanly (raw_pdu round-trips).
	b, err := json.Marshal(evs[1])
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	var back event.Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if string(back.RawPDU) != string(v1b) {
		t.Error("raw_pdu did not round-trip through JSON")
	}
}

// TestReceiver_FixtureReplay covers M1a DoD ①: a synthetic fixture written
// by trapgen gen --out and replayed by trapgen replay arrives as exactly
// the expected number of normalized events, all decodable, with the
// linkDown/linkUp kinds of the scenario.
func TestReceiver_FixtureReplay(t *testing.T) {
	// 1. Build the fixture (deterministic).
	scenarioYAML := `
version: 1
devices: 5
interfaces_per_device: 4
events:
  - kind: linkdown_up
    rate_per_min: 600
    hold: { min: 10ms, max: 50ms }
`
	sc, err := gen.LoadScenario(strings.NewReader(scenarioYAML))
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	fixture := filepath.Join(t.TempDir(), "m1a.fixture.pcap")
	g := gen.NewGenerator(sc, "m1a-dod")
	gstats, err := g.Run(context.Background(), gen.RunOptions{OutFile: fixture, Duration: 2 * time.Second})
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if gstats.Sent == 0 {
		t.Fatal("fixture is empty")
	}

	// 2. Receive.
	addr, events, stop := startReceiver(t)

	// 3. Replay the fixture into the receiver.
	rstats, err := replay.Run(context.Background(), replay.Options{
		File: fixture, Target: addr, Rate: 2000,
	}, &strings.Builder{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rstats.Sent != gstats.Sent {
		t.Fatalf("replay sent %d, fixture has %d", rstats.Sent, gstats.Sent)
	}

	waitFor(t, func() bool { return len(events()) >= rstats.Sent })
	stats := stop()

	if int(stats.Events.Load()) != rstats.Sent {
		t.Errorf("Events = %d, want %d (every replayed trap becomes exactly one event)", stats.Events.Load(), rstats.Sent)
	}
	if stats.DecodeFailed.Load() != 0 || stats.DroppedQueueFull.Load() != 0 {
		t.Errorf("decode_failed=%d dropped=%d, want 0/0", stats.DecodeFailed.Load(), stats.DroppedQueueFull.Load())
	}

	down, up := 0, 0
	for _, ev := range events() {
		switch ev.TrapOID {
		case "1.3.6.1.6.3.1.1.5.3":
			down++
		case "1.3.6.1.6.3.1.1.5.4":
			up++
		default:
			t.Errorf("unexpected trap_oid %q", ev.TrapOID)
		}
		if ev.Version != "v2c" || len(ev.Varbinds) != 5 {
			t.Errorf("unexpected event shape: %+v", ev)
		}
	}
	if down != up {
		t.Errorf("linkDown=%d linkUp=%d, want equal (gen flushes pending ups)", down, up)
	}
}
