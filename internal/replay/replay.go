// Package replay implements trapgen's pcap replay: reading a capture file,
// extracting the UDP payload of packets destined for a given port (the SNMP
// trap port by default), and re-sending those payloads to a target address
// at a controlled rate.
//
// This package does not interpret the SNMP payload — see LLD §3.2, HLD §5.1:
// M0a treats the UDP payload as an opaque byte string. Parsing it is the
// job of internal/snmpcodec, introduced in M0b.
package replay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/umadura88/sekisho/internal/pcapio"
)

// TrapPort is the standard SNMP trap destination port. Only packets whose
// UDP destination port equals this value are extracted from the capture.
const TrapPort = 162

// timingSpeed maps a --timing flag value to its playback speed multiplier:
// 1x for "original", 2x, 10x. An empty string means rate-controlled mode
// (Options.Rate is used instead) and is not a valid input to this function.
func timingSpeed(timing string) (float64, error) {
	switch timing {
	case "original":
		return 1, nil
	case "2x":
		return 2, nil
	case "10x":
		return 10, nil
	default:
		return 0, fmt.Errorf("replay: unknown --timing value %q (want original, 2x, or 10x)", timing)
	}
}

// Options configures a replay run. See cmd/trapgen's replay subcommand and
// plan.html §3.1 for the corresponding CLI flags.
type Options struct {
	// File is the path to the input pcap/pcapng capture.
	File string
	// Target is the destination host:port for the UDP payload.
	Target string
	// Rate, if > 0, paces sends to a fixed number of packets per second.
	// Mutually exclusive with Timing.
	Rate int
	// Timing, if non-empty, paces sends by replaying the capture's own
	// inter-packet arrival times, scaled by the given speed
	// ("original", "2x", "10x"). Mutually exclusive with Rate.
	Timing string
	// Loop replays the file from the beginning after reaching EOF.
	Loop bool
	// Count stops the run after this many packets have been sent (or
	// would have been sent, in DryRun mode). Zero means unlimited: one
	// pass over the file if Loop is false, or indefinitely if Loop is
	// true (bounded only by ctx cancellation).
	Count int
	// DryRun reports statistics without opening a network connection or
	// sending any packet.
	DryRun bool
}

// Stats summarizes one replay run.
type Stats struct {
	Total   int // packets read from the capture
	Matched int // packets with UDP dst port == TrapPort
	Sent    int // packets actually sent (or, in DryRun, that would be sent)
	Errors  int // packets that failed to decode or send
	Elapsed time.Duration
}

// Run executes a replay according to opts, writing a summary line to out
// on completion. It returns after the capture (or capture loops) are
// exhausted, Count is reached, or ctx is cancelled.
func Run(ctx context.Context, opts Options, out io.Writer) (Stats, error) {
	if opts.Rate > 0 && opts.Timing != "" {
		return Stats{}, errors.New("replay: --rate and --timing are mutually exclusive")
	}

	timing := opts.Timing
	var speed float64
	if opts.Rate <= 0 {
		if timing == "" {
			timing = "original" // default when neither flag is given
		}
		var err error
		speed, err = timingSpeed(timing)
		if err != nil {
			return Stats{}, err
		}
	}

	var conn net.Conn
	if !opts.DryRun {
		c, err := net.Dial("udp", opts.Target)
		if err != nil {
			return Stats{}, fmt.Errorf("replay: dial target %q: %w", opts.Target, err)
		}
		conn = c
		defer conn.Close()
	}

	start := time.Now()
	stats := Stats{}
	firstInPass := true
	var lastTS time.Time

sendLoop:
	for {
		f, err := os.Open(opts.File)
		if err != nil {
			return stats, fmt.Errorf("replay: open %q: %w", opts.File, err)
		}
		rdr, err := pcapio.NewReader(f)
		if err != nil {
			f.Close()
			return stats, fmt.Errorf("replay: read %q: %w", opts.File, err)
		}

		for {
			select {
			case <-ctx.Done():
				f.Close()
				break sendLoop
			default:
			}

			pkt, err := rdr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				stats.Errors++
				continue
			}
			stats.Total++

			payload, ok := matchTrapPayload(pkt)
			if !ok {
				continue
			}
			stats.Matched++

			if opts.Count > 0 && stats.Sent >= opts.Count {
				f.Close()
				break sendLoop
			}

			if opts.DryRun {
				stats.Sent++
				lastTS = pkt.Timestamp
				firstInPass = false
				continue
			}

			if opts.Rate > 0 {
				if stats.Sent > 0 {
					target := start.Add(time.Duration(stats.Sent) * time.Second / time.Duration(opts.Rate))
					sleepUntil(ctx, target)
				}
			} else if !firstInPass {
				delta := pkt.Timestamp.Sub(lastTS)
				if delta > 0 {
					time.Sleep(time.Duration(float64(delta) / speed))
				}
			}

			if _, err := conn.Write(payload); err != nil {
				stats.Errors++
			} else {
				stats.Sent++
			}
			lastTS = pkt.Timestamp
			firstInPass = false
		}
		f.Close()

		if !opts.Loop {
			break
		}
		firstInPass = true // inter-arrival pacing resets at the top of each loop
	}

	stats.Elapsed = time.Since(start)
	fmt.Fprintf(out, "total=%d matched=%d sent=%d errors=%d elapsed=%s\n",
		stats.Total, stats.Matched, stats.Sent, stats.Errors, stats.Elapsed)
	return stats, nil
}

// matchTrapPayload returns the UDP payload of pkt if it is an IPv4 or IPv6
// packet whose UDP destination port is TrapPort.
func matchTrapPayload(pkt *pcapio.Packet) ([]byte, bool) {
	udpLayer := pkt.Decoded.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil, false
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok || uint16(udp.DstPort) != TrapPort {
		return nil, false
	}
	return udp.Payload, true
}

// sleepUntil blocks until t or ctx is cancelled, whichever comes first.
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
