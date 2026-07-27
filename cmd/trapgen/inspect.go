package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/umadura88/sekisho/internal/inspect"
)

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	file := fs.String("file", "", "input pcap file (required)")
	jsonMode := fs.Bool("json", false, "emit one JSON object per decoded trap (decomposed varbinds)")
	limit := fs.Int("limit", 0, "stop printing per-trap output after N traps (statistics still cover the whole file)")
	statsOnly := fs.Bool("stats-only", false, "print only the summary")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: trapgen inspect --file traps.pcap [flags]

Decodes every UDP/162 payload in a capture and reports what it
contains: per-trap lines (or JSON), the v1/v2c mix, the decode success
rate, and trap kinds by frequency. Run this first on a capture taken
from a production monitoring server. OIDs are printed raw (MIB
resolution arrives in M1).

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
	if *file == "" {
		fs.Usage()
		return errors.New("--file is required")
	}

	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = inspect.Run(f, os.Stdout, inspect.Options{
		JSON:      *jsonMode,
		Limit:     *limit,
		StatsOnly: *statsOnly,
	})
	return err
}
