// Command sekisho is the trap monitoring engine (HLD/LLD in site/).
//
// M1a scope (plan.html §6.1): `sekisho serve` receives traps over UDP,
// decodes and normalizes them (RFC 3584 for v1), resolves the device
// identity, and emits one JSON line per event on stdout. Storage, MIB
// resolution, and the REST API arrive in M1b/M1c.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/umadura88/sekisho/internal/config"
	"github.com/umadura88/sekisho/internal/event"
	"github.com/umadura88/sekisho/internal/receiver"
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
	case "serve":
		err = runServe(ctx, os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "sekisho: unknown subcommand %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "sekisho %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `sekisho — SNMP trap monitoring engine

Usage:
  sekisho serve [--config sekisho.yaml | --bind host:port]

M1a: events are emitted as JSON Lines on stdout; statistics go to
stderr. See site/plan.html §6 for the milestone plan.
`)
}

func runServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to sekisho.yaml (listeners section)")
	bind := fs.String("bind", "", "UDP listen address (shortcut when no config file is used)")
	statsInterval := fs.Duration("stats-interval", 10*time.Second, "how often to log statistics to stderr (0 = only at exit)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sekisho serve [--config sekisho.yaml | --bind host:port]

Receives SNMP traps over UDP and emits one normalized event per line
(JSON) on stdout. Give either a config file with a listeners section,
or --bind for a quick start.

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

	var bindAddr string
	switch {
	case *configPath != "" && *bind != "":
		return errors.New("--config and --bind are mutually exclusive")
	case *configPath != "":
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		if len(cfg.Listeners) > 1 {
			fmt.Fprintf(os.Stderr, "sekisho: %d listeners configured; M1a serves only the first\n", len(cfg.Listeners))
		}
		bindAddr = cfg.Listeners[0].Bind
	case *bind != "":
		bindAddr = *bind
	default:
		fs.Usage()
		return errors.New("one of --config or --bind is required")
	}

	// stdout is shared by concurrent decoder workers; serialize writes.
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	r := receiver.New(receiver.Config{Bind: bindAddr}, func(ev *event.Event) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(ev)
	})
	if err := r.Listen(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "sekisho: listening on %s\n", r.LocalAddr())

	if *statsInterval > 0 {
		go func() {
			t := time.NewTicker(*statsInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					fmt.Fprintf(os.Stderr, "sekisho: %s\n", r.Stats())
				}
			}
		}()
	}

	err := r.Run(ctx)
	fmt.Fprintf(os.Stderr, "sekisho: final %s\n", r.Stats())
	return err
}
