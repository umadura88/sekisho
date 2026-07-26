package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/umadura88/sekisho/internal/sanitize"
)

func runSanitize(args []string) error {
	fs := flag.NewFlagSet("sanitize", flag.ContinueOnError)
	in := fs.String("in", "", "input pcap file (required)")
	out := fs.String("out", "", "output pcap file (required)")
	seed := fs.String("seed", "", "deterministic seed for IP mapping (required)")
	community := fs.String("community", "public", "replacement community string")
	scrub := fs.Bool("scrub-strings", false, "replace OCTET STRING/Opaque varbind values with scrubbed-<n>")
	report := fs.Bool("report", false, "print the original->anonymized IP mapping to stderr")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: trapgen sanitize --in real.pcap --out shareable.fixture.pcap --seed <s> [flags]

Anonymizes a real SNMP trap capture into a shareable fixture: every IPv4
address is remapped into the RFC 5737 documentation ranges, the community
string is replaced, and (with -scrub-strings) OCTET STRING/Opaque varbind
values are replaced with placeholders. Packets that cannot be decoded as
SNMP are dropped, not passed through.

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

	if *in == "" || *out == "" || *seed == "" {
		fs.Usage()
		return errors.New("--in, --out, and --seed are required")
	}

	mapper := sanitize.NewIPMapper(*seed)
	stats, err := sanitize.SanitizeFile(*in, *out, mapper, sanitize.Options{
		Community:    *community,
		ScrubStrings: *scrub,
	})
	if err != nil {
		return err
	}

	fmt.Printf("total=%d sanitized=%d skipped=%d\n", stats.Total, stats.Sanitized, stats.Skipped)
	if *report {
		for orig, anon := range mapper.Report() {
			fmt.Fprintf(os.Stderr, "%s -> %s\n", orig, anon)
		}
	}
	return nil
}
