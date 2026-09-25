package main

import (
	"testing"

	"github.com/shash01720/SNMP_NG/goimpl/internal/tree"
)

func TestContinuationQueueBasicOrder(t *testing.T) {
	q := newContinuationQueue()
	q.Add("/x@10")
	q.Add("/x@5")
	q.Add("/x@20")

	var order []int
	for {
		expr, ok := q.Next()
		if !ok {
			break
		}
		_, idx := tree.SplitResumeSuffix(expr)
		order = append(order, idx)
		q.MarkCovered(expr, 1) // pretend each fetch covered exactly its own index
	}
	want := []int{5, 10, 20}
	if len(order) != len(want) {
		t.Fatalf("got order %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("got order %v, want %v", order, want)
		}
	}
}

// This is the exact scenario diagnosed against the real IF-MIB demo:
// two continuations discovered from the same truncated batch, where the
// smaller-index one's eventual coverage subsumes the larger one.
func TestContinuationQueueSkipsSubsumedContinuation(t *testing.T) {
	q := newContinuationQueue()
	q.Add("/interfaces@38") // in-progress record's own nextSibling chain
	q.Add("/interfaces@42") // parent's nextSibling: the next full record

	expr, ok := q.Next()
	if !ok || expr != "/interfaces@38" {
		t.Fatalf("first pop = (%q, %v), want (/interfaces@38, true) -- smallest index first", expr, ok)
	}
	// Simulate the real response: fetching @38 returned 38 nodes, so it
	// covered [38, 76) -- which includes 42.
	q.MarkCovered(expr, 38)

	_, ok = q.Next()
	if ok {
		t.Fatal("expected /interfaces@42 to be skipped as already covered by @38's fetch, but Next() returned something")
	}
}

func TestContinuationQueueDoesNotSkipUncoveredContinuation(t *testing.T) {
	q := newContinuationQueue()
	q.Add("/interfaces@38")
	q.Add("/interfaces@100") // far beyond what @38's fetch will plausibly cover

	expr, _ := q.Next()
	if expr != "/interfaces@38" {
		t.Fatalf("first pop = %q, want /interfaces@38", expr)
	}
	// This time the fetch was small (heavily truncated): only covers [38, 42).
	q.MarkCovered(expr, 4)

	expr, ok := q.Next()
	if !ok || expr != "/interfaces@100" {
		t.Fatalf("second pop = (%q, %v), want (/interfaces@100, true) -- not covered, must still be fetched", expr, ok)
	}
}

func TestContinuationQueueExactDuplicateIgnored(t *testing.T) {
	q := newContinuationQueue()
	if !q.Add("/x@1") {
		t.Fatal("first Add should report true")
	}
	if q.Add("/x@1") {
		t.Fatal("exact duplicate Add should report false")
	}
	expr, ok := q.Next()
	if !ok || expr != "/x@1" {
		t.Fatalf("got (%q, %v)", expr, ok)
	}
	_, ok = q.Next()
	if ok {
		t.Fatal("expected no more entries after the one real one")
	}
}

func TestContinuationQueueDifferentBasesIndependent(t *testing.T) {
	q := newContinuationQueue()
	q.Add("/a@5")
	q.Add("/b@5")
	expr, _ := q.Next()
	q.MarkCovered(expr, 10) // covers /a@5..14, should NOT affect /b@5

	_, ok := q.Next()
	if !ok {
		t.Fatal("expected /b@5 to still be pending: coverage is per base expression")
	}
}
