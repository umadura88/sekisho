// Package receiver implements the left edge of sekisho's pipeline
// (LLD §10, plan.html §6.1): a UDP listener feeding a bounded channel,
// a decoder worker pool turning raw datagrams into normalized events, and
// self-observable statistics. Overflow is dropped and counted — never
// silently (HLD §12).
package receiver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/umadura88/sekisho/internal/event"
	"github.com/umadura88/sekisho/internal/snmpcodec"
)

// Config configures a Receiver. Zero values select the defaults from
// plan.html §6.1.
type Config struct {
	// Bind is the UDP listen address, e.g. "0.0.0.0:1620".
	Bind string
	// ChannelCap bounds the frame queue between the listener and the
	// decoder pool. Default 65,536.
	ChannelCap int
	// Workers is the decoder pool size. Default: number of CPUs.
	// Use 1 in tests that need in-order event delivery.
	Workers int
	// ReadBuffer is the requested SO_RCVBUF size. Default 8MB.
	ReadBuffer int

	// Now and NewID are injectable for deterministic tests. Defaults:
	// time.Now and UUIDv7.
	Now   func() time.Time
	NewID func() (string, error)
}

// Stats holds the receiver's self-observation counters (HLD §12). All
// fields are updated atomically and may be read concurrently.
type Stats struct {
	Received           atomic.Uint64 // datagrams read from the socket
	DroppedQueueFull   atomic.Uint64 // datagrams dropped: frame queue full
	DecodeFailed       atomic.Uint64 // not decodable as SNMP v1/v2c
	UnsupportedVersion atomic.Uint64 // valid SNMP, unsupported version (v3)
	NonTrapPDU         atomic.Uint64 // SNMP but not a trap (Get* etc.)
	Events             atomic.Uint64 // events successfully produced
}

// String renders a one-line snapshot for logs.
func (s *Stats) String() string {
	return fmt.Sprintf("received=%d dropped=%d decode_failed=%d unsupported_version=%d non_trap=%d events=%d",
		s.Received.Load(), s.DroppedQueueFull.Load(), s.DecodeFailed.Load(),
		s.UnsupportedVersion.Load(), s.NonTrapPDU.Load(), s.Events.Load())
}

// frame is one received datagram plus its receive context.
type frame struct {
	data []byte
	src  string
	ts   time.Time
}

// Receiver owns the socket, the bounded queue, and the decoder pool.
type Receiver struct {
	cfg    Config
	handle func(*event.Event)
	stats  Stats

	conn *net.UDPConn
}

// New creates a Receiver that calls handle for every normalized event.
// handle is called from decoder workers: with Workers > 1 it must be
// safe for concurrent use.
func New(cfg Config, handle func(*event.Event)) *Receiver {
	if cfg.ChannelCap <= 0 {
		cfg.ChannelCap = 65536
	}
	if cfg.Workers <= 0 {
		cfg.Workers = runtime.NumCPU()
	}
	if cfg.ReadBuffer <= 0 {
		cfg.ReadBuffer = 8 << 20
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewID == nil {
		cfg.NewID = func() (string, error) {
			id, err := uuid.NewV7()
			if err != nil {
				return "", err
			}
			return id.String(), nil
		}
	}
	return &Receiver{cfg: cfg, handle: handle}
}

// Stats exposes the live counters.
func (r *Receiver) Stats() *Stats { return &r.stats }

// LocalAddr returns the bound address once Run has opened the socket —
// useful with a ":0" bind in tests.
func (r *Receiver) LocalAddr() net.Addr {
	if r.conn == nil {
		return nil
	}
	return r.conn.LocalAddr()
}

// Listen opens the UDP socket. Split from Run so callers (and tests) can
// learn the bound address before traffic starts.
func (r *Receiver) Listen() error {
	addr, err := net.ResolveUDPAddr("udp", r.cfg.Bind)
	if err != nil {
		return fmt.Errorf("receiver: resolve %q: %w", r.cfg.Bind, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("receiver: listen %q: %w", r.cfg.Bind, err)
	}
	// Best effort: the OS may clamp this below the requested size.
	_ = conn.SetReadBuffer(r.cfg.ReadBuffer)
	r.conn = conn
	return nil
}

// Run processes traffic until ctx is cancelled. Listen must have been
// called first.
func (r *Receiver) Run(ctx context.Context) error {
	if r.conn == nil {
		if err := r.Listen(); err != nil {
			return err
		}
	}
	defer r.conn.Close()

	frames := make(chan frame, r.cfg.ChannelCap)

	var wg sync.WaitGroup
	for i := 0; i < r.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range frames {
				r.process(f)
			}
		}()
	}

	// Unblock the read loop when ctx is cancelled.
	go func() {
		<-ctx.Done()
		_ = r.conn.SetReadDeadline(time.Now())
	}()

	buf := make([]byte, 65535)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			close(frames)
			wg.Wait()
			return fmt.Errorf("receiver: read: %w", err)
		}
		r.stats.Received.Add(1)

		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case frames <- frame{data: data, src: src.String(), ts: r.cfg.Now()}:
		default:
			r.stats.DroppedQueueFull.Add(1)
		}
	}

	close(frames)
	wg.Wait()
	return nil
}

// process decodes one datagram and, if it is a trap, produces an event.
func (r *Receiver) process(f frame) {
	msg, err := snmpcodec.Decode(f.data)
	if err != nil {
		if errors.Is(err, snmpcodec.ErrUnsupportedVersion) {
			r.stats.UnsupportedVersion.Add(1)
		} else {
			r.stats.DecodeFailed.Add(1)
		}
		return
	}
	if msg.PDUType != snmpcodec.PDUTrapV1 && msg.PDUType != snmpcodec.PDUTrapV2 {
		r.stats.NonTrapPDU.Add(1)
		return
	}

	id, err := r.cfg.NewID()
	if err != nil {
		r.stats.DecodeFailed.Add(1)
		return
	}
	ev, err := event.Build(id, f.ts, f.src, msg, f.data)
	if err != nil {
		r.stats.DecodeFailed.Add(1)
		return
	}
	r.stats.Events.Add(1)
	r.handle(ev)
}
