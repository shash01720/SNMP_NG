package query

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

// Sample is one collected (key, value) observation -- deliberately decoupled
// from the tree package's Node type, so query has no dependency on it.
type Sample struct {
	Key   string
	Value wire.NodeValue
}

// Sampler evaluates a node expression against the live tree.
type Sampler interface {
	Sample(expression string) ([]Sample, error)
}

// ChangeWaiter is implemented by a Sampler whose underlying data source can
// notify on mutation, letting Query's onChange collection mode block until
// something actually changes instead of polling on a timer. It mirrors
// tree.Tree's own ChangedSince: see that method's doc comment for why the
// generation counter, not just the channel, is what makes this race-free.
type ChangeWaiter interface {
	ChangedSince(since uint64) (ch <-chan struct{}, gen uint64)
}

// ResultSink materializes a transfer's accumulated results (raw samples, or
// aggregation outputs) as nodes under the query's session's own
// QueryResults subtree, and pushes a Response to the client.
type ResultSink interface {
	DeliverResults(querySequenceNumber int64, results map[string][]wire.NodeValue) error
}

// ValidateQuery checks a Query's mode/interval/aggregation fields for
// internal consistency before a Runner is started for it.
func ValidateQuery(q *wire.Query) error {
	if q.TransferInterval < 0 {
		return fmt.Errorf("transferInterval must be >= 0")
	}
	switch q.CollectionMode.Kind {
	case wire.CollectOnce:
		// no further constraints: transferInterval may be 0 (transfer once,
		// immediately) or positive (harmless -- there's only one transfer).
	case wire.CollectInterval:
		if q.CollectionMode.Interval <= 0 {
			return fmt.Errorf("collectionMode interval must be > 0")
		}
		if q.TransferInterval <= 0 {
			return fmt.Errorf("transferInterval must be > 0 for a recurring (interval) query")
		}
	case wire.CollectOnChange:
		if q.TransferInterval <= 0 {
			return fmt.Errorf("transferInterval must be > 0 for an onChange query")
		}
	default:
		return fmt.Errorf("unknown collectionMode.kind %d", q.CollectionMode.Kind)
	}
	if (q.AggregationInterval != nil) != (q.AggregationMethod != nil) {
		return fmt.Errorf("aggregationInterval and aggregationMethod must be given together")
	}
	if q.AggregationInterval != nil && *q.AggregationInterval <= 0 {
		return fmt.Errorf("aggregationInterval must be > 0 when present")
	}
	return nil
}

// Runner drives one active Query's collection/aggregation/transfer
// pipeline, per node.asn's Query docs.
type Runner struct {
	query   wire.Query
	sampler Sampler
	sink    ResultSink
	cancel  context.CancelFunc

	mu         sync.Mutex
	collected  map[string][]wire.NodeValue // since the last aggregation (or transfer, if no aggregation)
	pending    map[string][]wire.NodeValue // aggregated/raw results accumulated since the last transfer
	lastValues map[string]wire.NodeValue   // onChange only: last value reported per key, for diffing
}

func NewRunner(q wire.Query, sampler Sampler, sink ResultSink) *Runner {
	return &Runner{
		query:      q,
		sampler:    sampler,
		sink:       sink,
		collected:  make(map[string][]wire.NodeValue),
		pending:    make(map[string][]wire.NodeValue),
		lastValues: make(map[string]wire.NodeValue),
	}
}

// Start runs the query, per CollectionMode: "once" performs exactly one
// collection/aggregation/transfer pass synchronously and returns; "interval"
// and "onChange" each launch a background goroutine (stopped via ctx or
// Stop()) driving their own recurring collect/aggregate/transfer cycle.
func (r *Runner) Start(ctx context.Context) {
	switch r.query.CollectionMode.Kind {
	case wire.CollectOnce:
		r.collect()
		if r.query.AggregationMethod != nil {
			r.aggregate()
		} else {
			r.promoteCollectedToPending()
		}
		r.transfer()
	case wire.CollectOnChange:
		runCtx, cancel := context.WithCancel(ctx)
		r.cancel = cancel
		go r.runOnChange(runCtx)
	default: // CollectInterval
		runCtx, cancel := context.WithCancel(ctx)
		r.cancel = cancel
		go r.run(runCtx)
	}
}

func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *Runner) run(ctx context.Context) {
	collectTicker := time.NewTicker(time.Duration(r.query.CollectionMode.Interval) * time.Second)
	defer collectTicker.Stop()

	var aggTickerC <-chan time.Time
	if r.query.AggregationInterval != nil {
		t := time.NewTicker(time.Duration(*r.query.AggregationInterval) * time.Second)
		defer t.Stop()
		aggTickerC = t.C
	}

	transferTicker := time.NewTicker(time.Duration(r.query.TransferInterval) * time.Second)
	defer transferTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-collectTicker.C:
			r.collect()
			if r.query.AggregationMethod == nil {
				r.promoteCollectedToPending()
			}
		case <-aggTickerC:
			r.aggregate()
		case <-transferTicker.C:
			r.transfer()
		}
	}
}

func (r *Runner) collect() {
	samples, err := r.sampler.Sample(r.query.NodeExpression)
	if err != nil {
		return // transient expression/match error: yield no samples this tick, try again next tick
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range samples {
		r.collected[s.Key] = append(r.collected[s.Key], s.Value)
	}
}

// runOnChange drives CollectOnChange: an immediate baseline collection
// (every currently-matched value, the way ON_CHANGE subscriptions
// conventionally establish their initial state), then one collect-and-diff
// pass per tree mutation instead of per timer tick. If the sampler doesn't
// support change notification (ChangeWaiter), only that baseline is ever
// collected -- there is nothing more this mode can do without it.
func (r *Runner) runOnChange(ctx context.Context) {
	r.collectChanges()
	if r.query.AggregationMethod == nil {
		r.promoteCollectedToPending()
	}
	r.transfer() // onChange's baseline is its own first result, delivered right away

	waiter, ok := r.sampler.(ChangeWaiter)
	if !ok {
		return
	}

	var aggTickerC <-chan time.Time
	if r.query.AggregationInterval != nil {
		t := time.NewTicker(time.Duration(*r.query.AggregationInterval) * time.Second)
		defer t.Stop()
		aggTickerC = t.C
	}

	transferTicker := time.NewTicker(time.Duration(r.query.TransferInterval) * time.Second)
	defer transferTicker.Stop()

	_, gen := waiter.ChangedSince(0)
	for {
		changed, g := waiter.ChangedSince(gen)
		gen = g
		select {
		case <-ctx.Done():
			return
		case <-changed:
			r.collectChanges()
			if r.query.AggregationMethod == nil {
				r.promoteCollectedToPending()
			}
		case <-aggTickerC:
			r.aggregate()
		case <-transferTicker.C:
			r.transfer()
		}
	}
}

// collectChanges is collect's onChange counterpart: it only forwards a
// sample when the value differs from the last one reported for that key
// (or the key wasn't matched before), per node.asn's CollectionMode docs.
func (r *Runner) collectChanges() {
	samples, err := r.sampler.Sample(r.query.NodeExpression)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range samples {
		if prev, seen := r.lastValues[s.Key]; seen && prev.Equal(s.Value) {
			continue
		}
		r.lastValues[s.Key] = s.Value
		r.collected[s.Key] = append(r.collected[s.Key], s.Value)
	}
}

func (r *Runner) aggregate() {
	r.mu.Lock()
	collected := r.collected
	r.collected = make(map[string][]wire.NodeValue)
	r.mu.Unlock()

	for key, samples := range collected {
		agg, err := Aggregate(*r.query.AggregationMethod, samples)
		if err != nil {
			continue // e.g. non-numeric samples for this key: skip, don't fail the whole query
		}
		r.mu.Lock()
		r.pending[key] = append(r.pending[key], agg)
		r.mu.Unlock()
	}
}

func (r *Runner) promoteCollectedToPending() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, samples := range r.collected {
		r.pending[key] = append(r.pending[key], samples...)
	}
	r.collected = make(map[string][]wire.NodeValue)
}

func (r *Runner) transfer() {
	r.mu.Lock()
	pending := r.pending
	r.pending = make(map[string][]wire.NodeValue)
	r.mu.Unlock()

	if len(pending) == 0 {
		return
	}
	// Best-effort: a delivery failure doesn't stop the query; the next
	// transfer tick retries with whatever's accumulated by then. (A ONCE
	// query that fails delivery simply produces no output -- there is no
	// "next tick" to retry on.)
	_ = r.sink.DeliverResults(r.query.SequenceNumber, pending)
}
