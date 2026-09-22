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

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

// --- Receiver: tracks what's been received, produces SummaryAck -----------

type Receiver struct {
	mu       sync.Mutex
	received map[int64]bool
}

func NewReceiver() *Receiver {
	return &Receiver{received: make(map[int64]bool)}
}

// MarkReceived records seq as received, returning true if this is the
// first time it's been seen (a duplicate delivery -- possible any time an
// ACK itself is lost and the sender retransmits something already
// received -- returns false, so callers can skip reprocessing it).
func (r *Receiver) MarkReceived(seq int64) (isNew bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.received[seq] {
		return false
	}
	r.received[seq] = true
	return true
}

// BuildAck returns a SummaryAck covering every sequence number received so
// far, as a compact list of inclusive ranges.
func (r *Receiver) BuildAck() *wire.SummaryAck {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.received) == 0 {
		return &wire.SummaryAck{}
	}
	seqs := make([]int64, 0, len(r.received))
	for s := range r.received {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	var ranges []wire.SequenceRange
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

// HandleAck removes every sequence number ack.Received covers from the
// pending (retransmit) set.
func (s *Sender) HandleAck(ack *wire.SummaryAck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range ack.Received {
		for seq := r.First; seq <= r.Last; seq++ {
			delete(s.pending, seq)
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
