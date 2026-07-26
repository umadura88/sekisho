package replay

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/umadura88/sekisho/internal/pcapio"
)

// writeTestCapture builds a small pcap file at path containing one
// Ethernet/IPv4/UDP frame per entry in pkts.
type testPkt struct {
	dstPort uint16
	payload []byte
	ts      time.Time
}

func writeTestCapture(t *testing.T, path string, pkts []testPkt) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create capture: %v", err)
	}
	defer f.Close()

	w, err := pcapio.NewWriter(f, layers.LinkTypeEthernet, 65535)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for _, p := range pkts {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
		}
		udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(p.dstPort)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("SetNetworkLayerForChecksum: %v", err)
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(p.payload)); err != nil {
			t.Fatalf("SerializeLayers: %v", err)
		}
		if err := w.WritePacket(p.ts, buf.Bytes()); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
}

// listenUDP starts a local UDP listener on an ephemeral port and returns
// its address plus a channel that receives every payload it reads.
func listenUDP(t *testing.T) (addr string, received chan []byte, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	ch := make(chan []byte, 64)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				close(done)
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			ch <- cp
		}
	}()
	return conn.LocalAddr().String(), ch, func() {
		conn.Close()
		<-done
	}
}

// TestRun_ExtractsAndSendsMatchedPayloads covers M0a DoD items ① and ③:
// matched (UDP/162) payloads are sent unmodified, in order, and
// non-matching packets are never sent.
func TestRun_ExtractsAndSendsMatchedPayloads(t *testing.T) {
	dir := t.TempDir()
	capFile := dir + "/traps.pcap"
	base := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	writeTestCapture(t, capFile, []testPkt{
		{dstPort: 162, payload: []byte("payload-A"), ts: base},
		{dstPort: 5000, payload: []byte("payload-B"), ts: base.Add(time.Millisecond)},
		{dstPort: 162, payload: []byte("payload-C"), ts: base.Add(2 * time.Millisecond)},
		{dstPort: 162, payload: []byte("payload-D"), ts: base.Add(3 * time.Millisecond)},
	})

	target, received, stop := listenUDP(t)
	defer stop()

	var out bytes.Buffer
	stats, err := Run(context.Background(), Options{
		File: capFile, Target: target, Timing: "original",
	}, &out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Total != 4 {
		t.Errorf("Total = %d, want 4", stats.Total)
	}
	if stats.Matched != 3 {
		t.Errorf("Matched = %d, want 3", stats.Matched)
	}
	if stats.Sent != 3 {
		t.Errorf("Sent = %d, want 3", stats.Sent)
	}
	if stats.Errors != 0 {
		t.Errorf("Errors = %d, want 0", stats.Errors)
	}

	want := [][]byte{[]byte("payload-A"), []byte("payload-C"), []byte("payload-D")}
	for i, w := range want {
		select {
		case got := <-received:
			if !bytes.Equal(got, w) {
				t.Errorf("payload %d = %q, want %q", i, got, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for payload %d (%q)", i, w)
		}
	}
	select {
	case extra := <-received:
		t.Errorf("received unexpected extra payload %q (non-matching packet must not be sent)", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestRun_DryRunSendsNothing covers M0a DoD item ④: --dry-run must not
// touch the network. The target is intentionally invalid — if Run ever
// tried to dial it, the run would fail.
func TestRun_DryRunSendsNothing(t *testing.T) {
	dir := t.TempDir()
	capFile := dir + "/traps.pcap"
	writeTestCapture(t, capFile, []testPkt{
		{dstPort: 162, payload: []byte("payload-A"), ts: time.Now()},
		{dstPort: 162, payload: []byte("payload-B"), ts: time.Now()},
	})

	var out bytes.Buffer
	stats, err := Run(context.Background(), Options{
		File: capFile, Target: "invalid target that must never be dialed", DryRun: true,
	}, &out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Matched != 2 || stats.Sent != 2 {
		t.Errorf("stats = %+v, want Matched=2 Sent=2 (dry-run still counts what would be sent)", stats)
	}
}

// TestRun_RatePacing covers M0a DoD item ②: at a fixed rate of 100 pps,
// sending 1,000 packets takes 10s within a tolerant margin. The capture
// loops (its own packets carry no meaningful timing in rate mode).
func TestRun_RatePacing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping ~10s rate-pacing DoD check under -short")
	}

	dir := t.TempDir()
	capFile := dir + "/traps.pcap"
	writeTestCapture(t, capFile, []testPkt{
		{dstPort: 162, payload: []byte("p1"), ts: time.Now()},
		{dstPort: 162, payload: []byte("p2"), ts: time.Now()},
	})

	target, received, stop := listenUDP(t)
	defer stop()
	go func() {
		for range received {
		}
	}()

	var out bytes.Buffer
	stats, err := Run(context.Background(), Options{
		File: capFile, Target: target, Rate: 100, Loop: true, Count: 1000,
	}, &out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if stats.Sent != 1000 {
		t.Fatalf("Sent = %d, want 1000", stats.Sent)
	}
	want := 10 * time.Second
	tolerance := want / 10 // ±10%
	if stats.Elapsed < want-tolerance || stats.Elapsed > want+tolerance {
		t.Errorf("Elapsed = %s, want %s ±10%%", stats.Elapsed, want)
	}
}

func TestRun_RateAndTimingMutuallyExclusive(t *testing.T) {
	var out bytes.Buffer
	_, err := Run(context.Background(), Options{
		File: "unused", Target: "127.0.0.1:1", Rate: 10, Timing: "original",
	}, &out)
	if err == nil {
		t.Fatal("Run with both Rate and Timing set: want error, got nil")
	}
}
