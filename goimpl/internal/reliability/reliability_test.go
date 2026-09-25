package reliability

import (
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

func TestReceiverBuildAckRanges(t *testing.T) {
	r := NewReceiver()
	for _, seq := range []int64{1, 2, 3, 5, 8, 9, 10} {
		if !r.MarkReceived(seq) {
			t.Fatalf("seq %d should be new", seq)
		}
	}
	if r.MarkReceived(5) {
		t.Fatalf("seq 5 should be a duplicate")
	}
	ack := r.BuildAck()
	want := []wire.SequenceRange{{First: 1, Last: 3}, {First: 5, Last: 5}, {First: 8, Last: 10}}
	if !reflect.DeepEqual(ack.Received, want) {
		t.Fatalf("got %+v, want %+v", ack.Received, want)
	}
}

// In-order traffic must not accumulate per-seq state: a long session is
// summarized by the single contiguous mark.
func TestReceiverStateStaysBoundedInOrder(t *testing.T) {
	r := NewReceiver()
	for seq := int64(1); seq <= 100000; seq++ {
		r.MarkReceived(seq)
	}
	if len(r.above) != 0 {
		t.Fatalf("held %d out-of-order seqs, want 0", len(r.above))
	}
	want := []wire.SequenceRange{{First: 1, Last: 100000}}
	if got := r.BuildAck().Received; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if r.MarkReceived(42) {
		t.Fatalf("seq 42 below the mark should be a duplicate")
	}
}

// A late arrival that fills the gap absorbs everything held above it.
func TestReceiverGapFillAdvancesMark(t *testing.T) {
	r := NewReceiver()
	for _, seq := range []int64{1, 3, 4, 5} {
		r.MarkReceived(seq)
	}
	if r.contiguous != 1 || len(r.above) != 3 {
		t.Fatalf("contiguous=%d above=%d, want 1 and 3", r.contiguous, len(r.above))
	}
	if !r.MarkReceived(2) {
		t.Fatalf("seq 2 should be new")
	}
	if r.contiguous != 5 || len(r.above) != 0 {
		t.Fatalf("contiguous=%d above=%d, want 5 and 0", r.contiguous, len(r.above))
	}
}

// A gap that never fills (its sender gave up) must not let the out-of-order
// set grow without limit.
func TestReceiverAbandonsPermanentGap(t *testing.T) {
	r := NewReceiver()
	r.MarkReceived(1)
	for seq := int64(3); seq <= 3+maxOutOfOrder+500; seq++ {
		r.MarkReceived(seq)
	}
	if len(r.above) > maxOutOfOrder {
		t.Fatalf("held %d out-of-order seqs, want <= %d", len(r.above), maxOutOfOrder)
	}
	if last := int64(3 + maxOutOfOrder + 500); r.contiguous != last {
		t.Fatalf("contiguous=%d, want %d once the gap at 2 is abandoned", r.contiguous, last)
	}
	if r.MarkReceived(2) {
		t.Fatalf("an abandoned seq arriving late should be treated as a duplicate")
	}
}

func TestReceiverAckRangesCapped(t *testing.T) {
	r := NewReceiver()
	for seq := int64(2); seq < 2+4*maxAckRanges; seq += 2 {
		r.MarkReceived(seq) // every other seq: one range each
	}
	ack := r.BuildAck()
	if len(ack.Received) != maxAckRanges {
		t.Fatalf("got %d ranges, want %d", len(ack.Received), maxAckRanges)
	}
	if ack.Received[0].First != 2 {
		t.Fatalf("the lowest ranges should be kept, got first=%d", ack.Received[0].First)
	}
}

func TestSenderHandleAckWideRange(t *testing.T) {
	sender := NewSender(func(p []byte) error { return nil }, time.Hour, 5, nil)
	sender.Send(1_000_000, []byte("a"))
	sender.Send(1_000_002, []byte("b"))
	sender.HandleAck(&wire.SummaryAck{Received: []wire.SequenceRange{{First: 1, Last: 1_000_001}}})
	if sender.Pending() != 1 {
		t.Fatalf("pending = %d, want 1 (only 1000002 unacked)", sender.Pending())
	}
}

func TestSenderRetransmitsUnackedAndStopsOnAck(t *testing.T) {
	var sent int64
	sender := NewSender(func(p []byte) error {
		atomic.AddInt64(&sent, 1)
		return nil
	}, 20*time.Millisecond, 5, nil)

	if err := sender.Send(1, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&sent); got != 1 {
		t.Fatalf("sent = %d, want 1 (initial send)", got)
	}
	if sender.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", sender.Pending())
	}

	time.Sleep(30 * time.Millisecond)
	sender.retransmitDue()
	if got := atomic.LoadInt64(&sent); got != 2 {
		t.Fatalf("sent = %d, want 2 (one retransmit)", got)
	}

	sender.HandleAck(&wire.SummaryAck{Received: []wire.SequenceRange{{First: 1, Last: 1}}})
	if sender.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 after ack", sender.Pending())
	}

	time.Sleep(30 * time.Millisecond)
	sender.retransmitDue()
	if got := atomic.LoadInt64(&sent); got != 2 {
		t.Fatalf("sent = %d, want still 2 (no retransmit after ack)", got)
	}
}

func TestSenderGivesUpAfterMaxAttempts(t *testing.T) {
	var gaveUp int64 = -1
	sender := NewSender(func(p []byte) error { return nil }, 5*time.Millisecond, 2, func(seq int64) {
		gaveUp = seq
	})
	sender.Send(7, []byte("x"))
	for i := 0; i < 5; i++ {
		time.Sleep(6 * time.Millisecond)
		sender.retransmitDue()
	}
	if gaveUp != 7 {
		t.Fatalf("onGiveUp seq = %d, want 7", gaveUp)
	}
	if sender.Pending() != 0 {
		t.Fatalf("pending = %d, want 0 after giving up", sender.Pending())
	}
}
