package query

import (
	"context"
	"math"
	"testing"

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
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

type fakeSink struct {
	delivered map[string][]wire.NodeValue
	querySeq  int64
	calls     int
}

func (f *fakeSink) DeliverResults(querySeq int64, results map[string][]wire.NodeValue) error {
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
	q := wire.Query{SequenceNumber: 42, NodeExpression: "/config/timeout", CollectionInterval: 0, TransferInterval: 0}
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
		CollectionInterval: 0, AggregationInterval: &aggInterval, AggregationMethod: &agg, TransferInterval: 0,
	}
	r := NewRunner(q, sampler, sink)
	r.Start(context.Background())

	got := sink.delivered["timeout"]
	if len(got) != 1 || got[0].Kind != wire.ValueReal || !almostEqual(got[0].Real, 30) {
		t.Fatalf("delivered = %+v", sink.delivered)
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
		{"once, no aggregation", wire.Query{CollectionInterval: 0, TransferInterval: 0}, true},
		{"recurring, no transfer", wire.Query{CollectionInterval: 60, TransferInterval: 0}, false},
		{"recurring with transfer", wire.Query{CollectionInterval: 60, TransferInterval: 600}, true},
		{"aggInterval without method", wire.Query{CollectionInterval: 60, TransferInterval: 600, AggregationInterval: &interval}, false},
		{"method without aggInterval", wire.Query{CollectionInterval: 60, TransferInterval: 600, AggregationMethod: &agg}, false},
		{"both present", wire.Query{CollectionInterval: 60, TransferInterval: 600, AggregationInterval: &interval, AggregationMethod: &agg}, true},
	}
	for _, c := range cases {
		err := ValidateQuery(&c.q)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
