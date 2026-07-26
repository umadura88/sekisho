package gen

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/umadura88/sekisho/internal/pcapio"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

const fixtureScenario = `
version: 1
devices: 5
interfaces_per_device: 4
events:
  - kind: linkdown_up
    rate_per_min: 600
    hold: { min: 10ms, max: 50ms }
  - kind: generic_alarm
    trap_oid: 1.3.6.1.4.1.99999.1.1
    rate_per_min: 300
`

func writeFixture(t *testing.T, path, seed string) {
	t.Helper()
	sc := loadTestScenario(t, fixtureScenario)
	g := NewGenerator(sc, seed)
	stats, err := g.Run(context.Background(), RunOptions{
		OutFile:  path,
		Duration: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Sent == 0 {
		t.Fatal("fixture run sent no packets")
	}
	if stats.Errors != 0 {
		t.Fatalf("fixture run had %d errors", stats.Errors)
	}
}

// TestFixture_ByteReproducible: the same (scenario, seed, duration) must
// produce a byte-identical fixture file — virtual-time timestamps over a
// fixed epoch, no wall-clock influence.
func TestFixture_ByteReproducible(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.fixture.pcap")
	p2 := filepath.Join(dir, "b.fixture.pcap")
	writeFixture(t, p1, "seed-x")
	writeFixture(t, p2, "seed-x")

	h1 := fileHash(t, p1)
	h2 := fileHash(t, p2)
	if h1 != h2 {
		t.Error("two fixture runs with the same seed produced different bytes")
	}

	p3 := filepath.Join(dir, "c.fixture.pcap")
	writeFixture(t, p3, "seed-y")
	if fileHash(t, p3) == h1 {
		t.Error("a different seed produced an identical fixture")
	}
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return sha256.Sum256(data)
}

// TestFixture_DecodableAndPaired: every packet in the fixture is UDP/162,
// decodes via snmpcodec, timestamps are monotonically non-decreasing from
// the fixed epoch, and every linkDown has a matching linkUp for the same
// (source, ifIndex) — the end-of-run flush guarantees pairing.
func TestFixture_DecodableAndPaired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.fixture.pcap")
	writeFixture(t, path, "seed-pair")

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rdr, err := pcapio.NewReader(f)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	type key struct {
		src     string
		ifIndex int64
	}
	open := make(map[key]int)
	var last time.Time
	n := 0
	for {
		pkt, err := rdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		n++

		if pkt.Timestamp.Before(last) {
			t.Errorf("packet %d timestamp %v is before previous %v", n, pkt.Timestamp, last)
		}
		last = pkt.Timestamp

		udpLayer := pkt.Decoded.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			t.Fatalf("packet %d: no UDP layer", n)
		}
		udp := udpLayer.(*layers.UDP)
		if udp.DstPort != 162 {
			t.Errorf("packet %d: dst port %v, want 162", n, udp.DstPort)
		}

		msg, err := snmpcodec.Decode(udp.Payload)
		if err != nil {
			t.Fatalf("packet %d: snmpcodec.Decode: %v", n, err)
		}

		ip4 := pkt.Decoded.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		trap := msg.Varbinds[1].Value.OID.String()
		switch trap {
		case "1.3.6.1.6.3.1.1.5.3": // linkDown
			k := key{src: ip4.SrcIP.String(), ifIndex: msg.Varbinds[2].Value.Int}
			open[k]++
		case "1.3.6.1.6.3.1.1.5.4": // linkUp
			k := key{src: ip4.SrcIP.String(), ifIndex: msg.Varbinds[2].Value.Int}
			open[k]--
		}
	}
	if n == 0 {
		t.Fatal("fixture contains no packets")
	}
	for k, v := range open {
		if v != 0 {
			t.Errorf("unbalanced linkDown/linkUp for %v: %+d", k, v)
		}
	}
}

// TestFixture_TargetAndOutMutuallyExclusive verifies option validation.
func TestFixture_TargetAndOutMutuallyExclusive(t *testing.T) {
	sc := loadTestScenario(t, "version: 1\ndevices: 1\ninterfaces_per_device: 1\n")
	g := NewGenerator(sc, "seed")
	_, err := g.Run(context.Background(), RunOptions{Target: "127.0.0.1:1", OutFile: "x.pcap"})
	if err == nil {
		t.Fatal("Run with both Target and OutFile: want error")
	}
	_, err = g.Run(context.Background(), RunOptions{})
	if err == nil {
		t.Fatal("Run with neither Target nor OutFile: want error")
	}
}

// TestFixture_LoadModeExactCount: in fixture mode, load mode writes exactly
// PPS×Duration packets, driven by virtual time alone (no wall-clock).
func TestFixture_LoadModeExactCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "load.fixture.pcap")
	sc := loadTestScenario(t, "version: 1\ndevices: 3\ninterfaces_per_device: 2\n")
	g := NewGenerator(sc, "seed")

	start := time.Now()
	stats, err := g.Run(context.Background(), RunOptions{
		OutFile:  path,
		PPS:      5000,
		Duration: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Sent != 10000 {
		t.Errorf("Sent = %d, want exactly 10000 (5000pps x 2s)", stats.Sent)
	}
	// Fixture mode must not pace in real time: writing 10k packets should
	// take far less than the 2s of virtual time they represent.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("fixture load mode took %v; it must not sleep through virtual time", elapsed)
	}

	var buf bytes.Buffer
	fdata, _ := os.ReadFile(path)
	buf.Write(fdata)
	rdr, err := pcapio.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		_, err := rdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 10000 {
		t.Errorf("fixture contains %d packets, want 10000", count)
	}
}
