package reliability

import (
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

func TestReceiverBuildAckRanges(t *testing.T) {
	r := NewReceiver()
	for _, seq := range []int64{0, 1, 2, 5, 8, 9, 10} {
		if !r.MarkReceived(seq) {
			t.Fatalf("seq %d should be new", seq)
		}
	}
	if r.MarkReceived(5) {
		t.Fatalf("seq 5 should be a duplicate")
	}
	ack := r.BuildAck()
	want := []wire.SequenceRange{{First: 0, Last: 2}, {First: 5, Last: 5}, {First: 8, Last: 10}}
	if !reflect.DeepEqual(ack.Received, want) {
		t.Fatalf("got %+v, want %+v", ack.Received, want)
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
