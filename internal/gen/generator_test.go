package gen

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/umadura88/sekisho/internal/snmpcodec"
)

func loadTestScenario(t *testing.T, yamlSrc string) *Scenario {
	t.Helper()
	sc, err := LoadScenario(strings.NewReader(yamlSrc))
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	return sc
}

// TestBuildLinkTrap_MatchesHLDShape verifies the generated linkDown/linkUp
// traps have exactly the varbind shape described in HLD §1.1.1 (Figure 1):
// sysUpTime, snmpTrapOID, ifIndex, ifAdminStatus, ifOperStatus, in order.
func TestBuildLinkTrap_MatchesHLDShape(t *testing.T) {
	sc := loadTestScenario(t, "version: 1\ndevices: 1\ninterfaces_per_device: 1\n")
	g := NewGenerator(sc, "seed")
	dev := g.devices[0]

	down := g.buildLinkTrap(dev, 1000, false, 42)
	payload, err := down.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := snmpcodec.Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(decoded.Varbinds) != 5 {
		t.Fatalf("len(Varbinds) = %d, want 5", len(decoded.Varbinds))
	}
	wantNames := []string{
		"1.3.6.1.2.1.1.3.0",
		"1.3.6.1.6.3.1.1.4.1.0",
		"1.3.6.1.2.1.2.2.1.1.1000",
		"1.3.6.1.2.1.2.2.1.7.1000",
		"1.3.6.1.2.1.2.2.1.8.1000",
	}
	for i, want := range wantNames {
		if got := decoded.Varbinds[i].Name.String(); got != want {
			t.Errorf("Varbinds[%d].Name = %q, want %q", i, got, want)
		}
	}
	if got := decoded.Varbinds[1].Value.OID.String(); got != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("snmpTrapOID value = %q, want linkDown OID", got)
	}
	if got := decoded.Varbinds[4].Value.Int; got != 2 {
		t.Errorf("ifOperStatus (down) = %d, want 2", got)
	}

	up := g.buildLinkTrap(dev, 1000, true, 43)
	upPayload, err := up.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	upDecoded, err := snmpcodec.Decode(upPayload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got := upDecoded.Varbinds[1].Value.OID.String(); got != "1.3.6.1.6.3.1.1.5.4" {
		t.Errorf("snmpTrapOID value = %q, want linkUp OID", got)
	}
	if got := upDecoded.Varbinds[4].Value.Int; got != 1 {
		t.Errorf("ifOperStatus (up) = %d, want 1", got)
	}
}

// captureSend returns a sendFunc that appends every payload to a slice.
func captureSend() (*[][]byte, func(sendMeta, []byte) error) {
	var sent [][]byte
	return &sent, func(_ sendMeta, p []byte) error {
		cp := append([]byte(nil), p...)
		sent = append(sent, cp)
		return nil
	}
}

func TestGenerator_LoadMode(t *testing.T) {
	sc := loadTestScenario(t, "version: 1\ndevices: 5\ninterfaces_per_device: 4\n")
	g := NewGenerator(sc, "seed")
	sent, send := captureSend()
	g.sendFunc = send

	stats, err := g.Run(context.Background(), RunOptions{PPS: 200, Duration: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}
	// ~40 packets expected (200pps * 0.2s); allow generous scheduling slack.
	if stats.Sent < 25 || stats.Sent > 60 {
		t.Errorf("Sent = %d, want roughly 40 (25-60)", stats.Sent)
	}
	if len(*sent) != stats.Sent {
		t.Fatalf("captured %d payloads, stats.Sent = %d", len(*sent), stats.Sent)
	}
	for i, p := range *sent {
		if _, err := snmpcodec.Decode(p); err != nil {
			t.Fatalf("payload %d does not decode: %v", i, err)
		}
	}
}

func TestGenerator_LoadModeRequiresDuration(t *testing.T) {
	sc := loadTestScenario(t, "version: 1\ndevices: 1\ninterfaces_per_device: 1\n")
	g := NewGenerator(sc, "seed")
	_, send := captureSend()
	g.sendFunc = send

	_, err := g.Run(context.Background(), RunOptions{PPS: 100})
	if err == nil {
		t.Fatal("Run with PPS set and no Duration: want error, got nil")
	}
}

// TestGenerator_Determinism verifies the same scenario+seed produces an
// identical sequence of encoded payloads across independent runs
// (plan.html §5.2's --seed determinism requirement).
func TestGenerator_Determinism(t *testing.T) {
	yamlSrc := `
version: 1
devices: 10
interfaces_per_device: 8
events:
  - kind: linkdown_up
    rate_per_min: 600
    hold: { min: 10ms, max: 50ms }
  - kind: generic_alarm
    trap_oid: 1.3.6.1.4.1.99999.1.1
    rate_per_min: 300
`
	run := func() [][]byte {
		sc := loadTestScenario(t, yamlSrc)
		g := NewGenerator(sc, "identical-seed")
		sent, send := captureSend()
		g.sendFunc = send
		if _, err := g.Run(context.Background(), RunOptions{Duration: 300 * time.Millisecond}); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return *sent
	}

	a := run()
	b := run()
	if len(a) == 0 {
		t.Fatal("first run sent no packets; nothing to compare")
	}
	if len(a) != len(b) {
		t.Fatalf("run lengths differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if string(a[i]) != string(b[i]) {
			t.Fatalf("payload %d differs between runs", i)
		}
	}
}

// TestGenerator_FlapSendsDownBeforeUp verifies a flap sequence alternates
// starting with down, per HLD's raise/clear pairing model.
func TestGenerator_FlapSendsDownBeforeUp(t *testing.T) {
	sc := loadTestScenario(t, `
version: 1
devices: 1
interfaces_per_device: 1
events:
  - kind: flap
    devices: 1
    interval: 20ms
    count: 4
`)
	g := NewGenerator(sc, "seed")
	sent, send := captureSend()
	g.sendFunc = send

	if _, err := g.Run(context.Background(), RunOptions{Duration: 200 * time.Millisecond}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(*sent) < 4 {
		t.Fatalf("sent %d packets, want at least 4 (count=4 flap sequence)", len(*sent))
	}
	for i, p := range *sent {
		decoded, err := snmpcodec.Decode(p)
		if err != nil {
			t.Fatalf("payload %d: decode: %v", i, err)
		}
		wantOID := "1.3.6.1.6.3.1.1.5.3" // linkDown
		if i%2 == 1 {
			wantOID = "1.3.6.1.6.3.1.1.5.4" // linkUp
		}
		if got := decoded.Varbinds[1].Value.OID.String(); got != wantOID {
			t.Errorf("packet %d snmpTrapOID = %q, want %q", i, got, wantOID)
		}
	}
}

func TestGenerator_GenericAlarmSeverityRange(t *testing.T) {
	sc := loadTestScenario(t, `
version: 1
devices: 1
interfaces_per_device: 1
events:
  - kind: generic_alarm
    trap_oid: 1.3.6.1.4.1.99999.1.1
    rate_per_min: 600
`)
	g := NewGenerator(sc, "seed")
	sent, send := captureSend()
	g.sendFunc = send

	if _, err := g.Run(context.Background(), RunOptions{Duration: 200 * time.Millisecond}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(*sent) == 0 {
		t.Fatal("no packets sent")
	}
	for i, p := range *sent {
		decoded, err := snmpcodec.Decode(p)
		if err != nil {
			t.Fatalf("payload %d: decode: %v", i, err)
		}
		if got := decoded.Varbinds[1].Value.OID.String(); got != "1.3.6.1.4.1.99999.1.1" {
			t.Errorf("packet %d trap OID = %q", i, got)
		}
		status := decoded.Varbinds[3].Value.Int
		if status < 1 || status > 4 {
			t.Errorf("packet %d status = %d, want 1..4", i, status)
		}
	}
}
