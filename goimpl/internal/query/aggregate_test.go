package query

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

func almostEqual(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestAggregateMinMaxMean(t *testing.T) {
	samples := []wire.NodeValue{
		wire.Integer32Value(10),
		wire.Integer32Value(20),
		wire.Integer32Value(30),
	}
	min, err := Aggregate(wire.AggregationMethod{Kind: wire.AggMin}, samples)
	if err != nil || min.Kind != wire.ValueReal || !almostEqual(min.Real, 10) {
		t.Fatalf("min: %+v, %v", min, err)
	}
	max, err := Aggregate(wire.AggregationMethod{Kind: wire.AggMax}, samples)
	if err != nil || !almostEqual(max.Real, 30) {
		t.Fatalf("max: %+v, %v", max, err)
	}
	mean, err := Aggregate(wire.AggregationMethod{Kind: wire.AggMean}, samples)
	if err != nil || !almostEqual(mean.Real, 20) {
		t.Fatalf("mean: %+v, %v", mean, err)
	}
}

func TestAggregateStdDev(t *testing.T) {
	// Population std dev of [2, 4, 4, 4, 5, 5, 7, 9] is 2.0 (classic example).
	samples := []wire.NodeValue{
		wire.Integer32Value(2), wire.Integer32Value(4), wire.Integer32Value(4), wire.Integer32Value(4),
		wire.Integer32Value(5), wire.Integer32Value(5), wire.Integer32Value(7), wire.Integer32Value(9),
	}
	sd, err := Aggregate(wire.AggregationMethod{Kind: wire.AggStdDev}, samples)
	if err != nil || !almostEqual(sd.Real, 2.0) {
		t.Fatalf("stddev: %+v, %v", sd, err)
	}
}

func TestAggregatePercentile(t *testing.T) {
	samples := []wire.NodeValue{
		wire.Integer32Value(1), wire.Integer32Value(2), wire.Integer32Value(3),
		wire.Integer32Value(4), wire.Integer32Value(5),
	}
	p50, err := Aggregate(wire.AggregationMethod{Kind: wire.AggPercentile, Percentile: 50}, samples)
	if err != nil || !almostEqual(p50.Real, 3) {
		t.Fatalf("p50: %+v, %v", p50, err)
	}
	p100, err := Aggregate(wire.AggregationMethod{Kind: wire.AggPercentile, Percentile: 100}, samples)
	if err != nil || !almostEqual(p100.Real, 5) {
		t.Fatalf("p100: %+v, %v", p100, err)
	}
	p0, err := Aggregate(wire.AggregationMethod{Kind: wire.AggPercentile, Percentile: 0}, samples)
	if err != nil || !almostEqual(p0.Real, 1) {
		t.Fatalf("p0: %+v, %v", p0, err)
	}
}

func TestAggregateRejectsNonNumeric(t *testing.T) {
	samples := []wire.NodeValue{wire.StringValue("hello")}
	_, err := Aggregate(wire.AggregationMethod{Kind: wire.AggMean}, samples)
	if err == nil {
		t.Fatal("expected an error for non-numeric samples")
	}
}

// --- Runner pipeline (ONCE path, no timers involved) -----------------------

type fakeSampler struct {
	samples []Sample
	err     error
}

func (f *fakeSampler) Sample(expression string) ([]Sample, error) { return f.samples, f.err }

// fakeSink is shared between the calling goroutine and, for interval/
// onChange queries, Runner's own background goroutine -- guarded by mu.
type fakeSink struct {
	mu        sync.Mutex
	delivered map[string][]wire.NodeValue
	querySeq  int64
	calls     int
}

func (f *fakeSink) DeliverResults(querySeq int64, results map[string][]wire.NodeValue) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = results
	f.querySeq = querySeq
	f.calls++
	return nil
}

func TestRunnerOnceNoAggregation(t *testing.T) {
	sampler := &fakeSampler{samples: []Sample{
		{Key: "timeout", Value: wire.Integer32Value(30)},
	}}
	sink := &fakeSink{}
	q := wire.Query{SequenceNumber: 42, NodeExpression: "/config/timeout", CollectionMode: wire.OnceMode(), TransferInterval: 0}
	r := NewRunner(q, sampler, sink)
	r.Start(context.Background())

	if sink.calls != 1 {
		t.Fatalf("calls = %d, want 1", sink.calls)
	}
	if sink.querySeq != 42 {
		t.Fatalf("querySeq = %d, want 42", sink.querySeq)
	}
	got := sink.delivered["timeout"]
	if len(got) != 1 || got[0].Integer32 != 30 {
		t.Fatalf("delivered = %+v", sink.delivered)
	}
}

func TestRunnerOnceWithAggregation(t *testing.T) {
	sampler := &fakeSampler{samples: []Sample{
		{Key: "timeout", Value: wire.Integer32Value(30)},
	}}
	sink := &fakeSink{}
	agg := wire.AggregationMethod{Kind: wire.AggMean}
	aggInterval := int64(1)
	q := wire.Query{
		SequenceNumber: 1, NodeExpression: "/config/timeout",
		CollectionMode: wire.OnceMode(), AggregationInterval: &aggInterval, AggregationMethod: &agg, TransferInterval: 0,
	}
	r := NewRunner(q, sampler, sink)
	r.Start(context.Background())

	got := sink.delivered["timeout"]
	if len(got) != 1 || got[0].Kind != wire.ValueReal || !almostEqual(got[0].Real, 30) {
		t.Fatalf("delivered = %+v", sink.delivered)
	}
}

// --- Runner pipeline (onChange path, driven by a fake ChangeWaiter) --------

// fakeChangeSampler is a Sampler + ChangeWaiter a test can drive
// deterministically -- push a new snapshot of samples and fire the change
// signal -- instead of relying on real tree mutations or timers.
type fakeChangeSampler struct {
	mu      sync.Mutex
	samples []Sample
	gen     uint64
	ch      chan struct{}
}

func newFakeChangeSampler(initial []Sample) *fakeChangeSampler {
	return &fakeChangeSampler{samples: initial, ch: make(chan struct{})}
}

func (f *fakeChangeSampler) Sample(expression string) ([]Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Sample, len(f.samples))
	copy(out, f.samples)
	return out, nil
}

func (f *fakeChangeSampler) ChangedSince(since uint64) (<-chan struct{}, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if since != f.gen {
		already := make(chan struct{})
		close(already)
		return already, f.gen
	}
	return f.ch, f.gen
}

// push replaces the current samples and wakes anyone waiting in
// ChangedSince, simulating a tree mutation.
func (f *fakeChangeSampler) push(samples []Sample) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.samples = samples
	close(f.ch)
	f.ch = make(chan struct{})
	f.gen++
}

// waitForCalls blocks until sink has recorded at least n DeliverResults
// calls, or fails the test after a generous timeout -- avoids sleep-based
// flakiness while still bounding a runaway test.
func waitForCalls(t *testing.T, sink *fakeSink, n int) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		sink.mu.Lock()
		calls := sink.calls
		sink.mu.Unlock()
		if calls >= n {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d DeliverResults call(s), got %d", n, calls)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestRunnerOnChangeDeliversBaselineImmediately(t *testing.T) {
	sampler := newFakeChangeSampler([]Sample{{Key: "ifOperStatus", Value: wire.Integer32Value(1)}})
	sink := &fakeSink{}
	q := wire.Query{SequenceNumber: 1, NodeExpression: "/interfaces/ifOperStatus", CollectionMode: wire.OnChangeMode(), TransferInterval: 3600}
	r := NewRunner(q, sampler, sink)
	r.Start(context.Background())
	defer r.Stop()

	waitForCalls(t, sink, 1)
	sink.mu.Lock()
	got := sink.delivered["ifOperStatus"]
	sink.mu.Unlock()
	if len(got) != 1 || got[0].Integer32 != 1 {
		t.Fatalf("baseline delivered = %+v", got)
	}
}

func TestRunnerOnChangeSkipsUnchangedValues(t *testing.T) {
	sampler := newFakeChangeSampler([]Sample{{Key: "ifOperStatus", Value: wire.Integer32Value(1)}})
	sink := &fakeSink{}
	q := wire.Query{SequenceNumber: 1, NodeExpression: "/interfaces/ifOperStatus", CollectionMode: wire.OnChangeMode(), TransferInterval: 3600}
	r := NewRunner(q, sampler, sink)
	r.Start(context.Background())
	defer r.Stop()
	waitForCalls(t, sink, 1) // baseline

	// An unrelated mutation fires the change signal, but the sampled value
	// is identical to what was already reported: nothing new to deliver.
	sampler.push([]Sample{{Key: "ifOperStatus", Value: wire.Integer32Value(1)}})
	time.Sleep(50 * time.Millisecond)
	sink.mu.Lock()
	calls := sink.calls
	sink.mu.Unlock()
	if calls != 1 {
		t.Fatalf("calls = %d after an unchanged value, want 1 (no spurious delivery)", calls)
	}
}

func TestRunnerOnChangeDeliversOnRealChange(t *testing.T) {
	sampler := newFakeChangeSampler([]Sample{{Key: "ifOperStatus", Value: wire.Integer32Value(1)}})
	sink := &fakeSink{}
	q := wire.Query{
		SequenceNumber: 1, NodeExpression: "/interfaces/ifOperStatus",
		CollectionMode: wire.OnChangeMode(), TransferInterval: 1, // 1s: short enough for the test to observe promptly
	}
	r := NewRunner(q, sampler, sink)
	r.Start(context.Background())
	defer r.Stop()
	waitForCalls(t, sink, 1) // baseline: status=1 (up)

	sampler.push([]Sample{{Key: "ifOperStatus", Value: wire.Integer32Value(2)}}) // link goes down
	waitForCalls(t, sink, 2)

	sink.mu.Lock()
	got := sink.delivered["ifOperStatus"]
	sink.mu.Unlock()
	if len(got) != 1 || got[0].Integer32 != 2 {
		t.Fatalf("second delivery = %+v, want a single sample with value 2", got)
	}
}

func TestValidateQuery(t *testing.T) {
	agg := wire.AggregationMethod{Kind: wire.AggMean}
	interval := int64(60)
	cases := []struct {
		name string
		q    wire.Query
		ok   bool
	}{
		{"once, no aggregation", wire.Query{CollectionMode: wire.OnceMode(), TransferInterval: 0}, true},
		{"interval, no transfer", wire.Query{CollectionMode: wire.IntervalMode(60), TransferInterval: 0}, false},
		{"interval with transfer", wire.Query{CollectionMode: wire.IntervalMode(60), TransferInterval: 600}, true},
		{"interval with non-positive interval", wire.Query{CollectionMode: wire.IntervalMode(0), TransferInterval: 600}, false},
		{"onChange, no transfer", wire.Query{CollectionMode: wire.OnChangeMode(), TransferInterval: 0}, false},
		{"onChange with transfer", wire.Query{CollectionMode: wire.OnChangeMode(), TransferInterval: 5}, true},
		{"aggInterval without method", wire.Query{CollectionMode: wire.IntervalMode(60), TransferInterval: 600, AggregationInterval: &interval}, false},
		{"method without aggInterval", wire.Query{CollectionMode: wire.IntervalMode(60), TransferInterval: 600, AggregationMethod: &agg}, false},
		{"both present", wire.Query{CollectionMode: wire.IntervalMode(60), TransferInterval: 600, AggregationInterval: &interval, AggregationMethod: &agg}, true},
	}
	for _, c := range cases {
		err := ValidateQuery(&c.q)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
