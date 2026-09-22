package query

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
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

// ResultSink materializes a transfer's accumulated results (raw samples, or
// aggregation outputs) as nodes under the query's session's own
// QueryResults subtree, and pushes a Response to the client.
type ResultSink interface {
	DeliverResults(querySequenceNumber int64, results map[string][]wire.NodeValue) error
}

// ValidateQuery checks a Query's interval/aggregation fields for internal
// consistency before a Runner is started for it.
func ValidateQuery(q *wire.Query) error {
	if q.CollectionInterval < 0 {
		return fmt.Errorf("collectionInterval must be >= 0")
	}
	if (q.AggregationInterval != nil) != (q.AggregationMethod != nil) {
		return fmt.Errorf("aggregationInterval and aggregationMethod must be given together")
	}
	if q.AggregationInterval != nil && *q.AggregationInterval <= 0 {
		return fmt.Errorf("aggregationInterval must be > 0 when present")
	}
	if q.TransferInterval < 0 {
		return fmt.Errorf("transferInterval must be >= 0")
	}
	if q.CollectionInterval > 0 && q.TransferInterval <= 0 {
		return fmt.Errorf("transferInterval must be > 0 for a recurring query (collectionInterval > 0)")
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

	mu        sync.Mutex
	collected map[string][]wire.NodeValue // since the last aggregation (or transfer, if no aggregation)
	pending   map[string][]wire.NodeValue // aggregated/raw results accumulated since the last transfer
}

func NewRunner(q wire.Query, sampler Sampler, sink ResultSink) *Runner {
	return &Runner{
		query:     q,
		sampler:   sampler,
		sink:      sink,
		collected: make(map[string][]wire.NodeValue),
		pending:   make(map[string][]wire.NodeValue),
	}
}

// Start runs the query. collectionInterval == 0 ("ONCE") performs exactly
// one collection/aggregation/transfer pass synchronously and returns;
// otherwise it launches a background goroutine (stopped via ctx or Stop())
// driving the recurring collect/aggregate/transfer ticks.
func (r *Runner) Start(ctx context.Context) {
	if r.query.CollectionInterval == 0 {
		r.collect()
		if r.query.AggregationMethod != nil {
			r.aggregate()
		} else {
			r.promoteCollectedToPending()
		}
		r.transfer()
		return
	}

	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	go r.run(runCtx)
}

func (r *Runner) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *Runner) run(ctx context.Context) {
	collectTicker := time.NewTicker(time.Duration(r.query.CollectionInterval) * time.Second)
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
