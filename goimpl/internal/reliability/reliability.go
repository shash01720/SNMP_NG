// Package reliability implements the thin reliable-but-UNORDERED delivery
// layer described in node.asn (SummaryAck): QUIC DATAGRAM frames (RFC 9221)
// are congestion-controlled and ack-eliciting at the QUIC layer, but QUIC
// itself never retransmits or reorders them for the application. Node data
// tolerates arbitrary reordering (see node.asn), so this layer only adds
// retransmission, not ordering, deliberately avoiding the head-of-line
// blocking a QUIC stream would impose.
//
// This is a fixed-interval retransmitter, not a TCP-style adaptive RTO
// estimator -- a reasonable simplification for a reference implementation;
// a production version would want RTT-based retransmit timing.
package reliability

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

// --- Receiver: tracks what's been received, produces SummaryAck -----------

// maxOutOfOrder bounds how many sequence numbers a Receiver holds above its
// contiguous high-water mark. A gap below them normally fills within a few
// retransmit intervals; one that outlives this many later arrivals belongs to
// a message its sender has already given up on (maxRetransmits *
// retransmitInterval is about 2s at current settings), so the Receiver
// stops waiting for it and moves the mark past it.
const maxOutOfOrder = 1024

// maxAckRanges caps the ranges in one SummaryAck so it always fits in a
// single datagram. Acks are cumulative and resent every ack interval, so a
// range left out now is reported by a later ack once the gaps below it
// close; the only cost is a redundant retransmit in the meantime.
const maxAckRanges = 64

// Receiver records which sequence numbers have arrived. Sequence numbers
// start at 1 (see node.asn). Memory is bounded: everything at or below
// `contiguous` is summarized by that one number, and only arrivals above it
// are held individually, at most maxOutOfOrder of them.
type Receiver struct {
	mu         sync.Mutex
	contiguous int64          // every seq in [1, contiguous] has been received
	above      map[int64]bool // received seqs > contiguous+1
}

func NewReceiver() *Receiver {
	return &Receiver{above: make(map[int64]bool)}
}

// MarkReceived records seq as received, returning true if this is the
// first time it's been seen (a duplicate delivery -- possible any time an
// ACK itself is lost and the sender retransmits something already
// received -- returns false, so callers can skip reprocessing it). A seq at
// or below the high-water mark counts as a duplicate, including one the
// Receiver stopped waiting for (see maxOutOfOrder).
func (r *Receiver) MarkReceived(seq int64) (isNew bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if seq <= r.contiguous || r.above[seq] {
		return false
	}
	r.above[seq] = true
	r.advance()
	for len(r.above) > maxOutOfOrder {
		// Give up on the oldest gap: jump the mark to just below the lowest
		// held seq, then absorb whatever is now contiguous.
		r.contiguous = r.lowestAbove() - 1
		r.advance()
	}
	return true
}

// advance moves contiguous forward over any held seqs that now follow it.
func (r *Receiver) advance() {
	for r.above[r.contiguous+1] {
		delete(r.above, r.contiguous+1)
		r.contiguous++
	}
}

func (r *Receiver) lowestAbove() int64 {
	first := true
	var low int64
	for s := range r.above {
		if first || s < low {
			low, first = s, false
		}
	}
	return low
}

// BuildAck returns a SummaryAck covering the sequence numbers received so
// far, as a compact list of inclusive ranges, lowest first and at most
// maxAckRanges of them.
func (r *Receiver) BuildAck() *wire.SummaryAck {
	r.mu.Lock()
	defer r.mu.Unlock()
	var ranges []wire.SequenceRange
	if r.contiguous > 0 {
		ranges = append(ranges, wire.SequenceRange{First: 1, Last: r.contiguous})
	}
	if len(r.above) > 0 {
		seqs := make([]int64, 0, len(r.above))
		for s := range r.above {
			seqs = append(seqs, s)
		}
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		start, end := seqs[0], seqs[0]
		for _, s := range seqs[1:] {
			if s == end+1 {
				end = s
				continue
			}
			ranges = append(ranges, wire.SequenceRange{First: start, Last: end})
			start, end = s, s
		}
		ranges = append(ranges, wire.SequenceRange{First: start, Last: end})
	}
	if len(ranges) > maxAckRanges {
		ranges = ranges[:maxAckRanges]
	}
	return &wire.SummaryAck{Received: ranges}
}

// --- Sender: retransmits whatever hasn't been acked ------------------------

type pending struct {
	payload  []byte
	lastSent time.Time
	attempts int
}

type Sender struct {
	mu                 sync.Mutex
	pending            map[int64]*pending
	sendFunc           func([]byte) error
	retransmitInterval time.Duration
	maxAttempts        int
	onGiveUp           func(seq int64) // called (outside the lock) when maxAttempts is exceeded
}

// NewSender. sendFunc does the actual transmission (e.g. QUIC
// SendDatagram); onGiveUp, if non-nil, is called when a message has been
// retransmitted maxAttempts times with no ack -- the caller decides what
// that means (e.g. tear down the session).
func NewSender(sendFunc func([]byte) error, retransmitInterval time.Duration, maxAttempts int, onGiveUp func(seq int64)) *Sender {
	return &Sender{
		pending:            make(map[int64]*pending),
		sendFunc:           sendFunc,
		retransmitInterval: retransmitInterval,
		maxAttempts:        maxAttempts,
		onGiveUp:           onGiveUp,
	}
}

// Send transmits payload now and tracks it as pending until acked.
func (s *Sender) Send(seq int64, payload []byte) error {
	s.mu.Lock()
	s.pending[seq] = &pending{payload: payload, lastSent: time.Now(), attempts: 1}
	s.mu.Unlock()
	return s.sendFunc(payload)
}

// Cancel removes seq from the pending (retransmit) set without it ever
// having been acknowledged. Used when a send is known to be permanently
// undeliverable as sent (e.g. QUIC's DatagramTooLargeError) so it isn't
// blindly retransmitted forever with the same oversized payload; the
// caller is expected to build a corrected payload and Send it (optionally
// reusing the same seq).
func (s *Sender) Cancel(seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, seq)
}

// HandleAck removes every sequence number ack.Received covers from the
// pending (retransmit) set. Acks are cumulative, so the first range
// usually spans the whole session so far; walking the pending set rather
// than each range keeps the cost proportional to what is unacknowledged.
func (s *Sender) HandleAck(ack *wire.SummaryAck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for seq := range s.pending {
		for _, r := range ack.Received {
			if seq >= r.First && seq <= r.Last {
				delete(s.pending, seq)
				break
			}
		}
	}
}

// Pending reports how many messages are currently awaiting acknowledgment.
func (s *Sender) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// RunRetransmitLoop blocks, periodically resending anything still pending
// past retransmitInterval, until ctx is done.
func (s *Sender) RunRetransmitLoop(ctx context.Context) {
	ticker := time.NewTicker(s.retransmitInterval / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.retransmitDue()
		}
	}
}

func (s *Sender) retransmitDue() {
	now := time.Now()
	var toResend [][]byte
	var toGiveUp []int64

	s.mu.Lock()
	for seq, p := range s.pending {
		if now.Sub(p.lastSent) < s.retransmitInterval {
			continue
		}
		if p.attempts >= s.maxAttempts {
			toGiveUp = append(toGiveUp, seq)
			delete(s.pending, seq)
			continue
		}
		p.attempts++
		p.lastSent = now
		toResend = append(toResend, p.payload)
	}
	s.mu.Unlock()

	for _, payload := range toResend {
		_ = s.sendFunc(payload) // best-effort; a send error here just means we'll try again next tick
	}
	if s.onGiveUp != nil {
		for _, seq := range toGiveUp {
			s.onGiveUp(seq)
		}
	}
}
