package tree

import (
	"testing"

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

func demoTree() *Tree {
	t := New()
	alice := &Node{Key: "user", Value: wire.StringValue("alice")}
	group1 := &Node{Key: "group", Value: wire.StringValue("admin")}
	users1 := &Node{Key: "users"}
	AppendChild(users1, alice)
	AppendChild(users1, group1)
	AppendChild(t.Root, users1)

	bob := &Node{Key: "user", Value: wire.StringValue("bob")}
	group2 := &Node{Key: "group", Value: wire.StringValue("user")}
	users2 := &Node{Key: "users"}
	AppendChild(users2, bob)
	AppendChild(users2, group2)
	AppendChild(t.Root, users2)

	carol := &Node{Key: "user", Value: wire.StringValue("carol")}
	group3 := &Node{Key: "group", Value: wire.StringValue("user")}
	users3 := &Node{Key: "users"}
	AppendChild(users3, carol)
	AppendChild(users3, group3)
	AppendChild(t.Root, users3)

	config := &Node{Key: "config"}
	AppendChild(config, &Node{Key: "timeout", Value: wire.StringValue("30")})
	AppendChild(config, &Node{Key: "retries", Value: wire.StringValue("3")})
	AppendChild(t.Root, config)

	return t
}

func TestGetUsers(t *testing.T) {
	tr := demoTree()
	nodes, err := tr.Get("/users")
	if err != nil {
		t.Fatal(err)
	}
	// 3 "users" top-level matches, each with 2 children = 9 nodes.
	if len(nodes) != 9 {
		t.Fatalf("got %d nodes, want 9", len(nodes))
	}
	if nodes[0].Key != "users" || nodes[0].FirstChild.Kind != wire.PointerOffset || nodes[0].FirstChild.Offset != 1 {
		t.Errorf("nodes[0] = %+v, want users with firstChild offset 1", nodes[0])
	}
	// chained via the top-level-match nextSibling fix
	if nodes[0].NextSibling.Kind != wire.PointerOffset || nodes[0].NextSibling.Offset != 3 {
		t.Errorf("nodes[0].NextSibling = %+v, want offset 3", nodes[0].NextSibling)
	}
}

func TestGetLeaf(t *testing.T) {
	tr := demoTree()
	nodes, err := tr.Get("/users/user=alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Key != "user" || string(nodes[0].Value.OctetString) != "alice" {
		t.Fatalf("got %+v", nodes)
	}
}

func TestGetNoMatch(t *testing.T) {
	tr := demoTree()
	nodes, err := tr.Get("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("got %d nodes, want 0", len(nodes))
	}
}

func TestSetUpdateValue(t *testing.T) {
	tr := demoTree()
	newValue := wire.StringValue("superadmin")
	err := tr.Set(&wire.Set{Target: wire.AbsolutePointer("/users/group=admin"), NewValue: &newValue})
	if err != nil {
		t.Fatal(err)
	}
	nodes, _ := tr.Get("/users/group=superadmin")
	if len(nodes) != 1 {
		t.Fatalf("value wasn't updated: %+v", nodes)
	}
}

// TestSetDeleteFirstChildByRelink exercises the delete-by-relink primitive
// (relinkFirstChild) directly at the package level, not through a Set
// expression targeting the "users" parent that contains alice.
//
// This surfaces a real, worth-flagging limitation of the expression
// language as it stands: the three "users" nodes in the demo tree are only
// distinguishable by their CHILDREN's values (alice/bob/carol), not by any
// key/value of their own (they're all just key="users", value=noValue). Set
// can only target a node by matching that node's own key/value (the same
// mechanism Get uses), so there is currently no way for a client to
// express "the users record whose child user=alice" as a Set.target and
// relink *that* node's firstChild directly. Deleting a specific record's
// first field this way needs either a richer query language (descendant/
// child predicates) or the client walking to the parent via a separate Get
// first and addressing it some other way -- neither of which node.asn
// provides yet. Tracked here rather than silently worked around.
func TestSetDeleteFirstChildByRelink(t *testing.T) {
	tr := demoTree()
	parent, err := tr.FindOne("/users/user=alice")
	if err != nil {
		t.Fatal(err)
	}
	parentNode := parent.Parent // the "users" node containing alice
	if parentNode == nil || parentNode.Key != "users" {
		t.Fatalf("unexpected tree shape: %+v", parentNode)
	}
	if len(parentNode.Children) != 2 || parentNode.Children[0].Key != "user" {
		t.Fatalf("unexpected children: %+v", parentNode.Children)
	}

	newFirst := parentNode.Children[1] // "group", alice's own nextSibling
	if err := relinkFirstChild(parentNode, newFirst); err != nil {
		t.Fatal(err)
	}
	if len(parentNode.Children) != 1 || parentNode.Children[0].Key != "group" {
		t.Fatalf("after relink, children = %+v", parentNode.Children)
	}
}

func TestSetDeleteViaNextSibling(t *testing.T) {
	tr := demoTree()
	config, err := tr.FindOne("/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Children) != 2 {
		t.Fatalf("unexpected config children: %+v", config.Children)
	}
	timeout := config.Children[0]
	retries := config.Children[1]
	_ = retries

	// Delete "retries" (the last child) by setting timeout's nextSibling to
	// none.
	err = tr.Set(&wire.Set{
		Target:         wire.AbsolutePointer("/config/timeout"),
		NewNextSibling: ptrNodePointer(wire.NonePointer()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Children) != 1 || config.Children[0] != timeout {
		t.Fatalf("after delete, config children = %+v", config.Children)
	}
}

func ptrNodePointer(p wire.NodePointer) *wire.NodePointer { return &p }

// --- FitToSize / continuation ---------------------------------------------

// byteMeasure is a stand-in "how big would this be on the wire" function
// for tests: each node costs a fixed number of "bytes" plus 1 per byte of
// key length, so results are easy to reason about without pulling in the
// wire package's real BER codec here.
func byteMeasure(nodes []wire.Node) int {
	total := 0
	for _, n := range nodes {
		total += 10 + len(n.Key)
	}
	return total
}

func TestFitToSizeNoTruncationNeeded(t *testing.T) {
	tr := demoTree()
	flat, resume, base, err := tr.GetFull("/config")
	if err != nil {
		t.Fatal(err)
	}
	window, truncated := FitToSize(flat, resume, base, 10000, byteMeasure)
	if truncated {
		t.Fatal("should not need truncation with a huge size budget")
	}
	if len(window) != len(flat)-resume {
		t.Fatalf("got %d nodes, want %d", len(window), len(flat)-resume)
	}
}

func TestFitToSizeTruncatesAndChains(t *testing.T) {
	tr := demoTree()
	flat, resume, base, err := tr.GetFull("/users")
	if err != nil {
		t.Fatal(err)
	}
	if len(flat) != 9 {
		t.Fatalf("expected 9 flattened nodes, got %d", len(flat))
	}

	// Budget for exactly one node (10 + len("users") = 15) plus a little
	// slack, but not enough for two.
	budget := byteMeasure(flat[0:1]) + 2
	window, truncated := FitToSize(flat, resume, base, budget, byteMeasure)
	if !truncated {
		t.Fatal("expected truncation")
	}
	if len(window) != 1 {
		t.Fatalf("got %d node(s), want 1", len(window))
	}
	if window[0].Key != "users" {
		t.Fatalf("got key %q, want users", window[0].Key)
	}
	if window[0].FirstChild.Kind != wire.PointerAbsolute {
		t.Fatalf("firstChild = %+v, want an absolute continuation pointer", window[0].FirstChild)
	}
	wantContinuation := base + "@1"
	if window[0].FirstChild.Absolute != wantContinuation {
		t.Fatalf("firstChild = %q, want %q", window[0].FirstChild.Absolute, wantContinuation)
	}

	// Follow the continuation: resuming at index 1 should reach "user"
	// (alice), whose own nextSibling (offset +1, to "group") is within
	// bounds this time and should NOT be rewritten.
	nextBase, nextResume := SplitResumeSuffix(wantContinuation)
	if nextBase != base || nextResume != 1 {
		t.Fatalf("SplitResumeSuffix(%q) = (%q, %d), want (%q, 1)", wantContinuation, nextBase, nextResume, base)
	}
	flat2, resume2, base2, err := tr.GetFull(wantContinuation)
	if err != nil {
		t.Fatal(err)
	}
	window2, truncated2 := FitToSize(flat2, resume2, base2, 10000, byteMeasure)
	if truncated2 {
		t.Fatal("should not need truncation with a huge size budget on the continuation")
	}
	if len(window2) != 8 || window2[0].Key != "user" {
		t.Fatalf("continuation window = %+v", window2)
	}
}

func TestFitToSizeCannotFitEvenOneNode(t *testing.T) {
	tr := demoTree()
	flat, resume, base, err := tr.GetFull("/config")
	if err != nil {
		t.Fatal(err)
	}
	window, truncated := FitToSize(flat, resume, base, 1, byteMeasure) // budget too small for anything
	if window != nil {
		t.Fatalf("expected no nodes to fit, got %+v", window)
	}
	if !truncated {
		t.Fatal("expected truncated=true when there was data but none of it fit")
	}
}
