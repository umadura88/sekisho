// Package sanitize turns a real SNMP trap capture into a shareable fixture:
// every IPv4 address (packet source/destination, the v1 agent-addr field,
// and any IpAddress-typed varbind) is remapped through an IPMapper, the
// community string is replaced, and — optionally — OCTET STRING/Opaque
// varbind values are scrubbed. See plan.html §4.
//
// Packets that cannot be parsed as IPv4/UDP/SNMP are dropped rather than
// passed through unmodified: sekisho's confidentiality rule (plan.html §1)
// is that nothing leaves this package without being deliberately
// anonymized, so an unparsed packet is a packet we cannot vouch for.
package sanitize

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/umadura88/sekisho/internal/pcapio"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

// syntheticMAC addresses used for the rebuilt Ethernet frame. The output's
// link-layer framing is not meaningful — it exists only so the payload can
// be written as a valid pcap and replayed by trapgen replay.
var (
	syntheticSrcMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	syntheticDstMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

// Options configures a sanitize run.
type Options struct {
	// Community replaces every message's community string. Defaults to
	// "public" if empty.
	Community string
	// ScrubStrings replaces every OCTET STRING and Opaque varbind value
	// with "scrubbed-<n>".
	ScrubStrings bool
}

// Stats summarizes one sanitize run.
type Stats struct {
	Total     int
	Sanitized int
	Skipped   int
}

// Sanitize reads a capture from in, anonymizes it using mapper and opts,
// and writes the result to out as a classic pcap (Ethernet-framed —
// see the package doc comment on link-layer framing). Warnings for
// skipped packets are written to warn.
func Sanitize(in io.Reader, out io.Writer, warn io.Writer, mapper *IPMapper, opts Options) (Stats, error) {
	rdr, err := pcapio.NewReader(in)
	if err != nil {
		return Stats{}, fmt.Errorf("sanitize: open reader: %w", err)
	}
	wtr, err := pcapio.NewWriter(out, layers.LinkTypeEthernet, 65535)
	if err != nil {
		return Stats{}, fmt.Errorf("sanitize: open writer: %w", err)
	}

	community := opts.Community
	if community == "" {
		community = "public"
	}

	var stats Stats
	strCounter := 0
	for {
		pkt, err := rdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, fmt.Errorf("sanitize: read packet %d: %w", stats.Total, err)
		}
		stats.Total++

		ip4Layer := pkt.Decoded.Layer(layers.LayerTypeIPv4)
		udpLayer := pkt.Decoded.Layer(layers.LayerTypeUDP)
		if ip4Layer == nil || udpLayer == nil {
			stats.Skipped++
			fmt.Fprintf(warn, "sanitize: skip packet %d: not IPv4/UDP\n", stats.Total)
			continue
		}
		ip4 := ip4Layer.(*layers.IPv4)
		udp := udpLayer.(*layers.UDP)

		msg, err := snmpcodec.Decode(udp.Payload)
		if err != nil {
			stats.Skipped++
			fmt.Fprintf(warn, "sanitize: skip packet %d: decode: %v\n", stats.Total, err)
			continue
		}

		msg.Community = community
		for i := range msg.Varbinds {
			switch msg.Varbinds[i].Value.Type {
			case snmpcodec.TypeIPAddress:
				msg.Varbinds[i].Value.IP = mapper.Map(msg.Varbinds[i].Value.IP)
			case snmpcodec.TypeOctetString, snmpcodec.TypeOpaque:
				if opts.ScrubStrings {
					strCounter++
					msg.Varbinds[i].Value.Str = []byte(fmt.Sprintf("scrubbed-%d", strCounter))
				}
			}
		}
		if msg.PDUType == snmpcodec.PDUTrapV1 {
			msg.AgentAddr = mapper.Map(msg.AgentAddr)
		}

		newPayload, err := msg.Encode()
		if err != nil {
			return stats, fmt.Errorf("sanitize: re-encode packet %d: %w", stats.Total, err)
		}

		newSrcIP := mapper.Map(ip4.SrcIP)
		newDstIP := mapper.Map(ip4.DstIP)

		frame, err := buildFrame(newSrcIP, newDstIP, udp.SrcPort, udp.DstPort, newPayload)
		if err != nil {
			return stats, fmt.Errorf("sanitize: rebuild packet %d: %w", stats.Total, err)
		}

		if err := wtr.WritePacket(pkt.Timestamp, frame); err != nil {
			return stats, fmt.Errorf("sanitize: write packet %d: %w", stats.Total, err)
		}
		stats.Sanitized++
	}
	return stats, nil
}

// buildFrame serializes a fresh Ethernet/IPv4/UDP frame carrying payload,
// with all header lengths and checksums recomputed by gopacket.
func buildFrame(srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, payload []byte) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC: syntheticSrcMAC, DstMAC: syntheticDstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP, DstIP: dstIP,
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SanitizeFile is a convenience wrapper around Sanitize for file paths, used
// by cmd/trapgen.
func SanitizeFile(inPath, outPath string, mapper *IPMapper, opts Options) (Stats, error) {
	inFile, err := os.Open(inPath)
	if err != nil {
		return Stats{}, fmt.Errorf("sanitize: open %q: %w", inPath, err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outPath)
	if err != nil {
		return Stats{}, fmt.Errorf("sanitize: create %q: %w", outPath, err)
	}
	defer outFile.Close()

	return Sanitize(inFile, outFile, os.Stderr, mapper, opts)
}
