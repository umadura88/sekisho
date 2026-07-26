package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/umadura88/sekisho/internal/replay"
)

func runReplay(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	file := fs.String("file", "", "input pcap file (required); only packets with UDP dst port 162 are replayed")
	target := fs.String("target", "", "destination host:port for the UDP payload (required)")
	rate := fs.Int("rate", 0, "fixed packets/sec pacing (mutually exclusive with -timing)")
	timing := fs.String("timing", "", "replay at the capture's own inter-packet timing: original, 2x, or 10x (default: original, unless -rate is set)")
	loop := fs.Bool("loop", false, "restart from the beginning of the file at EOF")
	count := fs.Int("count", 0, "stop after sending this many packets (default: all matched packets once)")
	dryRun := fs.Bool("dry-run", false, "report statistics without sending anything")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: trapgen replay --file traps.pcap --target host:port [flags]

Replays packets from a pcap/pcapng capture whose UDP destination port is
162, sending their unmodified payload to --target.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *file == "" || *target == "" {
		fs.Usage()
		return errors.New("--file and --target are required")
	}

	_, err := replay.Run(ctx, replay.Options{
		File:   *file,
		Target: *target,
		Rate:   *rate,
		Timing: *timing,
		Loop:   *loop,
		Count:  *count,
		DryRun: *dryRun,
	}, os.Stdout)
	return err
}
