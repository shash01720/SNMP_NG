package main

import "github.com/shashi/snmp-ng/goimpl/internal/tree"

// continuationQueue tracks pending Get continuations discovered while
// following a truncated result (see followGet in main.go), deduplicating
// more aggressively than exact-string matching.
//
// A wide/bushy tree can dangle more than one pointer within the SAME
// truncated batch: e.g. fetching /interfaces can produce both an
// in-progress record's own nextSibling continuation ("/interfaces@42")
// and that record's parent's nextSibling continuation
// ("/interfaces@38", pointing to the very next record, which sits
// earlier in the flattened array than 42 since the parent node comes
// before its own children). Both are valid, syntactically distinct
// pointers, but resuming at the smaller index and reading forward will
// cover the larger index's data too, once far enough -- so naively
// fetching both independently, as if unrelated, redundantly re-fetches
// a large, overlapping range. Measured on the real IF-MIB demo data:
// 51 round trips instead of a theoretical minimum of ~13, delivering
// 1931 total nodes for only 460 unique ones (a ~4.2x redundancy).
//
// This type fixes that by (a) always dequeuing the SMALLEST pending
// resume index per base expression first, and (b) recording, after each
// actual fetch, exactly which index range that response covered
// ([resumeIndex, resumeIndex+len(nodes))) -- then skipping any other
// pending (or newly discovered) continuation whose index already falls
// inside a covered range, since a real response has already proven that
// data was delivered. This is safe (never drops data: a continuation is
// only skipped once an actual response is known to have covered its
// index, not on a guess) and directly eliminates the redundant fetches,
// rather than just capping their damage.
type continuationQueue struct {
	pending []pendingContinuation
	seen    map[string]bool           // cheap first-pass exact-string dedup
	covered map[string][]coveredRange // per base expression
}

type pendingContinuation struct {
	expr string
	base string
	idx  int
}

type coveredRange struct{ start, end int } // [start, end)

func newContinuationQueue() *continuationQueue {
	return &continuationQueue{
		seen:    make(map[string]bool),
		covered: make(map[string][]coveredRange),
	}
}

// Add enqueues expr for fetching, unless it's an exact repeat of
// something already seen or its index already falls within a range a
// prior fetch is known to have covered. Reports whether it was actually
// enqueued, so a caller can count real pending work (e.g. against a
// loop-guard limit) rather than every discovered-but-redundant pointer.
func (q *continuationQueue) Add(expr string) bool {
	if q.seen[expr] {
		return false
	}
	q.seen[expr] = true
	base, idx := tree.SplitResumeSuffix(expr)
	if q.isCovered(base, idx) {
		return false
	}
	q.pending = append(q.pending, pendingContinuation{expr: expr, base: base, idx: idx})
	return true
}

// Next pops the pending continuation with the smallest resume index
// (ties broken by discovery order), skipping over any whose coverage was
// recorded after it was queued. Returns ("", false) once nothing useful
// remains.
func (q *continuationQueue) Next() (string, bool) {
	for len(q.pending) > 0 {
		best := 0
		for i := 1; i < len(q.pending); i++ {
			if q.pending[i].idx < q.pending[best].idx {
				best = i
			}
		}
		next := q.pending[best]
		q.pending = append(q.pending[:best], q.pending[best+1:]...)
		if q.isCovered(next.base, next.idx) {
			continue
		}
		return next.expr, true
	}
	return "", false
}

// MarkCovered records that fetching `expr` returned `count` nodes, so
// the corresponding index range for its base expression is now known to
// be covered. Call this after every real fetch, successful or not
// (count == 0 is a harmless no-op).
func (q *continuationQueue) MarkCovered(expr string, count int) {
	if count <= 0 {
		return
	}
	base, resumeIndex := tree.SplitResumeSuffix(expr)
	q.covered[base] = append(q.covered[base], coveredRange{resumeIndex, resumeIndex + count})
}

func (q *continuationQueue) isCovered(base string, idx int) bool {
	for _, r := range q.covered[base] {
		if idx >= r.start && idx < r.end {
			return true
		}
	}
	return false
}
