// Command trapgen is sekisho's Trap emulator: it replays captured traps
// from a pcap file (M0a) and generates synthetic trap traffic from a
// scenario (M0c), either sending over UDP or writing shareable pcap
// fixtures.
//
// Real captures are for local replay only and must never enter the
// repository (plan.html §1); publishable fixtures are synthetic, produced
// with "trapgen gen --out". A capture sanitizer was built and then
// deliberately removed: trap enterprise OIDs are public vendor
// identifiers that cannot be anonymized without destroying the capture's
// meaning (plan.html §4).
//
// See site/plan.html §3–§5 for the full command specification.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "replay":
		err = runReplay(ctx, os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "gen":
		err = runGen(ctx, os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "trapgen: unknown subcommand %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "trapgen %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `trapgen — sekisho's SNMP trap emulator

Usage:
  trapgen replay  --file traps.pcap --target host:port [flags]
  trapgen inspect --file traps.pcap [flags]
  trapgen gen     --scenario scenario.yaml (--target host:port | --out fixture.pcap) [flags]

Run "trapgen <subcommand> -h" for flags specific to each subcommand.
See site/plan.html in the sekisho repository for the full specification.
`)
}
