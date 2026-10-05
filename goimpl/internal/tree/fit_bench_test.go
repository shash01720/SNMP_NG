package tree

import (
	"fmt"
	"testing"

	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

// leafPush builds a flattened timestamp-rooted subtree of n leaves, like a
// Query push, and a measure() that marshals the real Response envelope.
func leafPush(n int) ([]wire.Node, func([]wire.Node) int) {
	parent := &Node{Key: "p", Value: wire.NoValue()}
	entries := make([]Entry, n)
	for i := range entries {
		entries[i] = Entry{Key: fmt.Sprintf("m%04d", i), Value: wire.Counter64Value(uint64(i) * 1000003)}
	}
	flat := New().AppendLeafSubtree(parent, "2026-10-05T13:04:49.091716000Z", entries)
	measure := func(nodes []wire.Node) int {
		return len(wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: &wire.Response{SequenceNumber: 1, InReplyTo: 1, Nodes: nodes}}))
	}
	return flat, measure
}

func BenchmarkFitToSizeLeaves(b *testing.B) {
	for _, n := range []int{100, 1000, 4000} {
		flat, measure := leafPush(n)
		base := "/Sessions/Connection-ID\\=0123456789abcdef/QueryResults/Query-SequenceNumber\\=1/2026-10-05T13:04:49.091716000Z"
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				w, _ := FitToSize(flat, 0, base, 1300, measure)
				if len(w) == 0 {
					b.Fatal("nothing fit")
				}
			}
		})
	}
}

// fitExhaustive is FitToSize's original algorithm: try every window size from
// the full remainder downward.
func fitExhaustive(flat []wire.Node, resumeIndex int, base string, maxSize int, measure func([]wire.Node) int) ([]wire.Node, bool) {
	total := len(flat) - resumeIndex
	for n := total; n > 0; n-- {
		c := fixupWindow(flat, resumeIndex, n, base)
		if measure(c) <= maxSize {
			return c, n < total
		}
	}
	return nil, total > 0
}

// The binary search must pick the same window as the exhaustive search, over
// shapes with real pointer structure (flat leaves; deep trees whose
// continuation pointers sit at several depths) and across budgets.
func TestFitToSizeMatchesExhaustiveSearch(t *testing.T) {
	flatLeaves, measure := leafPush(120)

	deep := New()
	for i := 0; i < 8; i++ {
		rec := &Node{Key: fmt.Sprintf("rec%02d", i), Value: wire.NoValue()}
		AppendChild(deep.Root, rec)
		for j := 0; j < 4; j++ {
			sub := &Node{Key: fmt.Sprintf("grp%d", j), Value: wire.NoValue()}
			AppendChild(rec, sub)
			for k := 0; k < 5; k++ {
				AppendChild(sub, &Node{Key: fmt.Sprintf("leaf%d", k), Value: wire.Counter32Value(uint32(i*100 + j*10 + k))})
			}
		}
	}
	deepFlat := FlattenMatches(deep.Root.Children)

	base := "/Sessions/Connection-ID\\=0123456789abcdef/QueryResults/Query-SequenceNumber\\=1/x"
	for name, flat := range map[string][]wire.Node{"flat leaves": flatLeaves, "deep tree": deepFlat} {
		for _, resume := range []int{0, 7, len(flat) / 2} {
			for budget := 120; budget <= 1500; budget += 83 {
				got, gt := FitToSize(flat, resume, base, budget, measure)
				want, wt := fitExhaustive(flat, resume, base, budget, measure)
				if len(got) != len(want) || gt != wt {
					t.Fatalf("%s resume=%d budget=%d: binary search gave %d nodes (truncated=%v), exhaustive %d (truncated=%v)",
						name, resume, budget, len(got), gt, len(want), wt)
				}
				if len(got) > 0 && measure(got) > budget {
					t.Fatalf("%s resume=%d budget=%d: returned a window of %d bytes", name, resume, budget, measure(got))
				}
			}
		}
	}
}
