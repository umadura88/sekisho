package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/umadura88/sekisho/internal/gen"
)

func runGen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	scenarioPath := fs.String("scenario", "", "scenario YAML file (required)")
	target := fs.String("target", "", "destination host:port (mutually exclusive with -out)")
	out := fs.String("out", "", "write a pcap fixture instead of sending; byte-reproducible for a given scenario+seed (mutually exclusive with -target)")
	seed := fs.String("seed", "default-seed", "deterministic seed for randomness")
	pps := fs.Int("pps", 0, "load mode: flat packets/sec, ignoring the scenario's own rates (requires -duration)")
	durationStr := fs.String("duration", "", "how long to run (e.g. 5m); required with -pps, defaults to 60s in scenario mode")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: trapgen gen --scenario scenario.yaml (--target host:port | --out fixture.pcap) [flags]

Generates synthetic SNMP traps: either following the scenario's own
event rates and hold times (default), or as a flat-rate load stream
for throughput testing (-pps). With --out, traps are written to a pcap
fixture file instead of being sent — the supported way to produce
publishable test fixtures (real captures must never be committed).

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

	if *scenarioPath == "" || (*target == "" && *out == "") {
		fs.Usage()
		return errors.New("--scenario and one of --target / --out are required")
	}

	var duration time.Duration
	if *durationStr != "" {
		d, err := time.ParseDuration(*durationStr)
		if err != nil {
			return fmt.Errorf("--duration: %w", err)
		}
		duration = d
	}

	f, err := os.Open(*scenarioPath)
	if err != nil {
		return err
	}
	defer f.Close()

	sc, err := gen.LoadScenario(f)
	if err != nil {
		return err
	}

	g := gen.NewGenerator(sc, *seed)
	stats, err := g.Run(ctx, gen.RunOptions{
		Target:   *target,
		OutFile:  *out,
		PPS:      *pps,
		Duration: duration,
	})
	if err != nil {
		return err
	}

	fmt.Printf("sent=%d errors=%d elapsed=%s\n", stats.Sent, stats.Errors, stats.Elapsed)
	return nil
}
