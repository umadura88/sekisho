// Package inspect implements trapgen's capture inspection: decoding every
// UDP/162 payload in a pcap with internal/snmpcodec and reporting what the
// capture actually contains — trap kinds by frequency, version mix, and
// the decode success rate. It is the first thing to run on a capture taken
// from a production monitoring server: it answers "what is arriving?"
// before any of sekisho's routing or storage exists, and it validates the
// codec against real vendor traffic.
//
// No MIB resolution happens here (that is M1b); OIDs are printed raw.
package inspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/umadura88/sekisho/internal/pcapio"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

// TrapPort is the UDP destination port selecting packets to inspect.
const TrapPort = 162

// maxErrorSamples caps how many decode-failure examples are kept.
const maxErrorSamples = 5

// Options configures an inspection run.
type Options struct {
	// JSON emits one JSON object per decoded trap instead of a summary
	// line.
	JSON bool
	// Limit stops printing per-trap output after this many traps (0 =
	// no limit). Statistics still cover the whole file.
	Limit int
	// StatsOnly suppresses per-trap output entirely.
	StatsOnly bool
}

// Stats summarizes one inspection run.
type Stats struct {
	Total       int // packets in the capture
	Matched     int // UDP/162 packets
	Decoded     int // matched packets that decoded as SNMP
	Failures    int // matched packets that did not decode
	V1, V2c     int // decoded, by SNMP version
	Unsupported int // valid SNMP but an unsupported version (v3 etc.)

	Freq      map[string]int // trap OID (dotted) -> count
	ErrSample []string       // first few decode error messages
}

// varbindJSON is the JSON shape of one varbind in --json mode.
type varbindJSON struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// trapJSON is the JSON shape of one decoded trap in --json mode.
type trapJSON struct {
	Time      string        `json:"time"`
	Src       string        `json:"src"`
	Version   string        `json:"version"`
	Community string        `json:"community"`
	TrapOID   string        `json:"trap_oid"`
	Varbinds  []varbindJSON `json:"varbinds"`
}

// Run inspects the capture read from r, writing per-trap output and a
// final summary to out.
func Run(r io.Reader, out io.Writer, opts Options) (Stats, error) {
	rdr, err := pcapio.NewReader(r)
	if err != nil {
		return Stats{}, fmt.Errorf("inspect: open reader: %w", err)
	}

	stats := Stats{Freq: make(map[string]int)}
	printed := 0
	consecutiveReadErrors := 0

	for {
		pkt, err := rdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A persistently failing reader (corrupt capture) must not
			// spin forever; give up after a bounded number of attempts.
			consecutiveReadErrors++
			if consecutiveReadErrors >= 10 {
				fmt.Fprintf(out, "inspect: giving up after %d consecutive read errors (last: %v)\n", consecutiveReadErrors, err)
				break
			}
			continue
		}
		consecutiveReadErrors = 0
		stats.Total++

		udpLayer := pkt.Decoded.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp := udpLayer.(*layers.UDP)
		if uint16(udp.DstPort) != TrapPort {
			continue
		}
		stats.Matched++

		msg, err := snmpcodec.Decode(udp.Payload)
		if err != nil {
			if errors.Is(err, snmpcodec.ErrUnsupportedVersion) {
				stats.Unsupported++
			} else {
				stats.Failures++
				if len(stats.ErrSample) < maxErrorSamples {
					stats.ErrSample = append(stats.ErrSample, err.Error())
				}
			}
			continue
		}
		stats.Decoded++

		version := "v2c"
		if msg.Version == snmpcodec.VersionV1 {
			version = "v1"
			stats.V1++
		} else {
			stats.V2c++
		}

		trapOID := "(no snmpTrapOID varbind)"
		if o, ok := msg.TrapOID(); ok {
			trapOID = o.String()
		}
		stats.Freq[trapOID]++

		if opts.StatsOnly || (opts.Limit > 0 && printed >= opts.Limit) {
			continue
		}
		printed++

		src := sourceOf(pkt, msg)
		if opts.JSON {
			enc, err := json.Marshal(trapJSON{
				Time:      pkt.Timestamp.UTC().Format(time.RFC3339Nano),
				Src:       src,
				Version:   version,
				Community: msg.Community,
				TrapOID:   trapOID,
				Varbinds:  varbindsOf(msg),
			})
			if err != nil {
				return stats, fmt.Errorf("inspect: marshal: %w", err)
			}
			fmt.Fprintln(out, string(enc))
		} else {
			fmt.Fprintf(out, "%s  %-15s %-3s community=%s trap=%s varbinds=%d\n",
				pkt.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
				src, version, msg.Community, trapOID, len(msg.Varbinds))
		}
	}

	writeSummary(out, &stats)
	return stats, nil
}

// sourceOf returns the best available source identity: the v1 agent-addr
// when present, otherwise the packet's IPv4 source address.
func sourceOf(pkt *pcapio.Packet, m *snmpcodec.Message) string {
	if m.PDUType == snmpcodec.PDUTrapV1 && m.AgentAddr != nil && !m.AgentAddr.IsUnspecified() {
		return m.AgentAddr.String()
	}
	if l := pkt.Decoded.Layer(layers.LayerTypeIPv4); l != nil {
		return l.(*layers.IPv4).SrcIP.String()
	}
	if l := pkt.Decoded.Layer(layers.LayerTypeIPv6); l != nil {
		return l.(*layers.IPv6).SrcIP.String()
	}
	return "?"
}

func varbindsOf(m *snmpcodec.Message) []varbindJSON {
	out := make([]varbindJSON, 0, len(m.Varbinds))
	for _, vb := range m.Varbinds {
		out = append(out, varbindJSON{
			OID:   vb.Name.String(),
			Type:  vb.Value.Type.String(),
			Value: vb.Value.DisplayString(),
		})
	}
	return out
}

func writeSummary(out io.Writer, s *Stats) {
	fmt.Fprintf(out, "\n--- summary ---\n")
	fmt.Fprintf(out, "packets=%d matched(udp/162)=%d decoded=%d failures=%d unsupported-version=%d  v1=%d v2c=%d\n",
		s.Total, s.Matched, s.Decoded, s.Failures, s.Unsupported, s.V1, s.V2c)

	if len(s.ErrSample) > 0 {
		fmt.Fprintf(out, "decode error samples:\n")
		for _, e := range s.ErrSample {
			fmt.Fprintf(out, "  - %s\n", e)
		}
	}

	if len(s.Freq) == 0 {
		return
	}
	type kv struct {
		oid   string
		count int
	}
	freq := make([]kv, 0, len(s.Freq))
	for oid, c := range s.Freq {
		freq = append(freq, kv{oid, c})
	}
	sort.Slice(freq, func(i, j int) bool {
		if freq[i].count != freq[j].count {
			return freq[i].count > freq[j].count
		}
		return freq[i].oid < freq[j].oid
	})
	fmt.Fprintf(out, "trap kinds by frequency:\n")
	for i, f := range freq {
		if i >= 20 {
			fmt.Fprintf(out, "  ... and %d more kinds\n", len(freq)-20)
			break
		}
		fmt.Fprintf(out, "  %7d  %s\n", f.count, f.oid)
	}
}
