package tree

import (
	"testing"

	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
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
	touched, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/users/group=admin", NewValue: &newValue},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 1 {
		t.Fatalf("touched = %+v, want 1 node", touched)
	}
	nodes, _ := tr.Get("/users/group=superadmin")
	if len(nodes) != 1 {
		t.Fatalf("value wasn't updated: %+v", nodes)
	}
}

// TestSetUpdateValueMultiMatch exercises Set's new bulk capability: a
// single edit's target can match more than one node (like Get), and
// newValue is applied to every match.
func TestSetUpdateValueMultiMatch(t *testing.T) {
	tr := demoTree()
	newValue := wire.StringValue("member")
	touched, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/users/group=user", NewValue: &newValue}, // matches bob's and carol's group nodes
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 2 {
		t.Fatalf("touched = %+v, want 2 nodes", touched)
	}
	nodes, _ := tr.Get("/users/group=member")
	if len(nodes) != 2 {
		t.Fatalf("value wasn't updated on both matches: %+v", nodes)
	}
}

// TestSetMultipleEdits exercises a single Set request carrying several
// distinct target expressions, per node.asn's Set docs.
func TestSetMultipleEdits(t *testing.T) {
	tr := demoTree()
	aliceGroup := wire.StringValue("root")
	timeout := wire.StringValue("60")
	touched, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/users/group=admin", NewValue: &aliceGroup},
		{Target: "/config/timeout", NewValue: &timeout},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 2 {
		t.Fatalf("touched = %+v, want 2 nodes", touched)
	}
	if nodes, _ := tr.Get("/users/group=root"); len(nodes) != 1 {
		t.Fatalf("first edit didn't apply: %+v", nodes)
	}
	if nodes, _ := tr.Get("/config/timeout=60"); len(nodes) != 1 {
		t.Fatalf("second edit didn't apply: %+v", nodes)
	}
}

// TestSetZeroMatchIsNotAnError checks the idempotent-PATCH stance Set's
// value edits take (matching Get's own "empty match isn't an error"
// behavior): a target that currently matches nothing is a no-op, not a
// failure, since a retried at-least-once request must not start erroring
// once its effect has already landed.
func TestSetZeroMatchIsNotAnError(t *testing.T) {
	tr := demoTree()
	v := wire.StringValue("x")
	touched, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/nonexistent", NewValue: &v},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 0 {
		t.Fatalf("touched = %+v, want none", touched)
	}
}

// TestSetStructuralEditRequiresExactlyOneMatch checks that
// newFirstChild/newNextSibling reject an ambiguous or empty target
// up front, before any edit in the request is applied.
func TestSetStructuralEditRequiresExactlyOneMatch(t *testing.T) {
	tr := demoTree()
	before, _ := tr.Get("/config/timeout")

	_, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/users/user", NewNextSibling: ptrNodePointer(wire.NonePointer())}, // matches 3 nodes (alice/bob/carol)
	}}, nil)
	if err == nil {
		t.Fatal("expected an error for a structural edit matching 3 nodes")
	}
	after, _ := tr.Get("/config/timeout")
	if len(before) != len(after) {
		t.Fatalf("tree was mutated despite the rejected edit: before=%+v after=%+v", before, after)
	}
}

// TestSetAtomicRollbackOnConflict is the case applySetPlans's rollback
// exists for: two structural edits in one request whose plans were both
// resolved against the SAME pre-request tree, but the second edit's target
// is spliced out of its parent's Children by the first edit before the
// second one applies. Before relinkFirstChild/relinkNextSibling learned to
// check indexOfChild for -1, this panicked (a negative slice index)
// instead of erroring; now it must surface as a normal error, and the
// first edit's already-applied mutation must be rolled back so the whole
// request is genuinely atomic.
func TestSetAtomicRollbackOnConflict(t *testing.T) {
	tr := demoTree()
	config, err := tr.FindOne("/config")
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Children) != 2 || config.Children[0].Key != "timeout" || config.Children[1].Key != "retries" {
		t.Fatalf("unexpected config children: %+v", config.Children)
	}

	_, err = tr.Set(&wire.Set{Edits: []wire.SetEdit{
		// Edit 1: drop "retries" by making "timeout" the last child.
		{Target: "/config/timeout", NewNextSibling: ptrNodePointer(wire.NonePointer())},
		// Edit 2: resolved against the PRE-request tree (retries still
		// existed then), so this plans fine -- but by the time it's
		// APPLIED, edit 1 has already removed retries from config's
		// Children.
		{Target: "/config/retries", NewNextSibling: ptrNodePointer(wire.NonePointer())},
	}}, nil)
	if err == nil {
		t.Fatal("expected an error from the conflicting second edit")
	}
	if len(config.Children) != 2 || config.Children[0].Key != "timeout" || config.Children[1].Key != "retries" {
		t.Fatalf("edit 1 wasn't rolled back after edit 2 failed: config children = %+v", config.Children)
	}
}

// --- CreateStaged / Set's newParent (staging + commit) ----------------------

// TestCreateStagedNested checks that CreateStaged can build a multi-level
// subtree under stagingRoot by repeatedly naming an already-created node as
// the next call's parent, per node.asn's Create docs.
func TestCreateStagedNested(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)

	iface, err := tr.CreateStaged(stagingRoot, "", "interface", wire.NoValue())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.CreateStaged(stagingRoot, "/NewNodes/interface", "ifDescr", wire.StringValue("eth9"))
	if err != nil {
		t.Fatal(err)
	}
	if len(iface.Children) != 1 || iface.Children[0].Key != "ifDescr" {
		t.Fatalf("iface children = %+v, want [ifDescr]", iface.Children)
	}
}

// TestCreateStagedRejectsOutsideStaging checks CreateStaged's confinement:
// a parent expression resolving to a node outside stagingRoot's own subtree
// is rejected, not silently allowed to graft into live config.
func TestCreateStagedRejectsOutsideStaging(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)

	_, err := tr.CreateStaged(stagingRoot, "/config", "sneaky", wire.NoValue())
	if err == nil {
		t.Fatal("expected an error for a parent outside the staging subtree")
	}
	config, _ := tr.FindOne("/config")
	for _, c := range config.Children {
		if c.Key == "sneaky" {
			t.Fatal("the node was created under /config despite the rejected parent")
		}
	}
}

// TestSetNewParentCommitsStagedSubtree is the scenario this feature exists
// for: build a subtree under a session's own staged NewNodes across several
// Create calls, then attach its root into live config with one Set carrying
// newParent -- addressing NETCONF's candidate/commit gap for new subtrees
// (see SetEdit's node.asn docs).
func TestSetNewParentCommitsStagedSubtree(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)

	iface, err := tr.CreateStaged(stagingRoot, "", "interface", wire.NoValue())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.CreateStaged(stagingRoot, "/NewNodes/interface", "ifDescr", wire.StringValue("eth9")); err != nil {
		t.Fatal(err)
	}

	// Not reachable from live config yet.
	if nodes, _ := tr.Get("/config/interface"); len(nodes) != 0 {
		t.Fatalf("staged subtree should not be reachable from /config yet: %+v", nodes)
	}

	newParent := "/config"
	touched, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/NewNodes/interface", NewParent: &newParent},
	}}, stagingRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(touched) != 1 || touched[0] != iface {
		t.Fatalf("touched = %+v, want [iface]", touched)
	}

	// Now reachable from live config, whole subtree intact...
	nodes, err := tr.Get("/config/interface")
	if err != nil || len(nodes) != 2 { // interface + its ifDescr child
		t.Fatalf("got %+v, err=%v, want the interface and its child under /config", nodes, err)
	}
	// ...and gone from staging.
	if len(stagingRoot.Children) != 0 {
		t.Fatalf("staging root still has children after commit: %+v", stagingRoot.Children)
	}
}

// TestSetNewParentRejectsNonStagedTarget checks the "target must currently
// be staged" rule: a client can't reparent an arbitrary live config node
// via newParent, only something it created and hasn't committed yet.
func TestSetNewParentRejectsNonStagedTarget(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)

	newParent := "/config"
	_, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/users/user=alice", NewParent: &newParent},
	}}, stagingRoot)
	if err == nil {
		t.Fatal("expected an error: alice's node isn't part of this session's staged nodes")
	}
}

// TestSetNewParentRejectsCycle checks that attaching a staged subtree under
// one of its own descendants is rejected rather than corrupting the tree.
func TestSetNewParentRejectsCycle(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)

	if _, err := tr.CreateStaged(stagingRoot, "", "parent", wire.NoValue()); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.CreateStaged(stagingRoot, "/NewNodes/parent", "child", wire.NoValue()); err != nil {
		t.Fatal(err)
	}

	newParent := "/NewNodes/parent/child"
	_, err := tr.Set(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/NewNodes/parent", NewParent: &newParent},
	}}, stagingRoot)
	if err == nil {
		t.Fatal("expected a cycle error: parent can't become a child of its own child")
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
	_, err = tr.Set(&wire.Set{Edits: []wire.SetEdit{{
		Target:         "/config/timeout",
		NewNextSibling: ptrNodePointer(wire.NonePointer()),
	}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Children) != 1 || config.Children[0] != timeout {
		t.Fatalf("after delete, config children = %+v", config.Children)
	}
}

func ptrNodePointer(p wire.NodePointer) *wire.NodePointer { return &p }

// --- Delete -----------------------------------------------------------------

func TestDeleteSingleNode(t *testing.T) {
	tr := demoTree()
	config, err := tr.FindOne("/config")
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := tr.Delete([]string{"/config/retries"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].Key != "retries" {
		t.Fatalf("deleted = %+v, want [retries]", deleted)
	}
	if len(config.Children) != 1 || config.Children[0].Key != "timeout" {
		t.Fatalf("config children after delete = %+v", config.Children)
	}
}

// TestDeleteAddressesTheNodeItself, not its parent -- Delete closes the
// "how do I relink around this" gap, but NOT the separate "how do I
// address a container node that's only distinguishable by a descendant's
// value" gap TestSetDeleteFirstChildByRelink documents: deleting
// "/users/user=alice" removes just the "user" leaf, leaving its "users"
// container behind with only "group" as a child, not the whole record.
func TestDeleteAddressesTheNodeItself(t *testing.T) {
	tr := demoTree()
	deleted, err := tr.Delete([]string{"/users/user=alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].Key != "user" {
		t.Fatalf("deleted = %+v", deleted)
	}
	nodes, _ := tr.Get("/users/user=alice")
	if len(nodes) != 0 {
		t.Fatalf("alice's user node should be gone: %+v", nodes)
	}
	// The containing "users" record is still there, minus that one child.
	remaining, _ := tr.Get("/users/group=admin")
	if len(remaining) != 1 {
		t.Fatalf("alice's sibling group node should remain: %+v", remaining)
	}
}

// TestDeleteMultiMatch exercises Delete's regex-multi-match capability.
func TestDeleteMultiMatch(t *testing.T) {
	tr := demoTree()
	deleted, err := tr.Delete([]string{"/users/group=user"}) // bob's and carol's group nodes
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %+v, want 2 nodes", deleted)
	}
	remaining, _ := tr.Get("/users/group=user")
	if len(remaining) != 0 {
		t.Fatalf("expected no group=user nodes left: %+v", remaining)
	}
}

// TestDeleteMultipleTargets exercises a single Delete request carrying
// several distinct target expressions.
func TestDeleteMultipleTargets(t *testing.T) {
	tr := demoTree()
	deleted, err := tr.Delete([]string{"/config/timeout", "/config/retries"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %+v, want 2 nodes", deleted)
	}
	config, _ := tr.FindOne("/config")
	if len(config.Children) != 0 {
		t.Fatalf("config children after delete = %+v", config.Children)
	}
}

// TestDeleteZeroMatchIsNotAnError checks Delete's idempotent stance: a
// target matching nothing (e.g. a retry of an already-applied delete,
// possible under this protocol's at-least-once delivery) must not error.
func TestDeleteZeroMatchIsNotAnError(t *testing.T) {
	tr := demoTree()
	deleted, err := tr.Delete([]string{"/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted = %+v, want none", deleted)
	}
}

// TestDeleteOverlappingTargetsDeduplicates checks that a node matched by
// more than one of the given target expressions is only reported once
// (and only actually removed once, which would otherwise panic on the
// second, stale removeChild call).
func TestDeleteOverlappingTargetsDeduplicates(t *testing.T) {
	tr := demoTree()
	deleted, err := tr.Delete([]string{"/config/timeout", "/config/t.*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].Key != "timeout" {
		t.Fatalf("deleted = %+v, want exactly one (deduplicated) node", deleted)
	}
}

// --- IsReachable --------------------------------------------------------

func TestIsReachableRootAndLiveNodes(t *testing.T) {
	tr := demoTree()
	if !tr.IsReachable(tr.Root) {
		t.Fatal("Root should be reachable from itself")
	}
	config, err := tr.FindOne("/config")
	if err != nil {
		t.Fatal(err)
	}
	if !tr.IsReachable(config) {
		t.Fatal("/config should be reachable")
	}
	timeout := config.Children[0]
	if !tr.IsReachable(timeout) {
		t.Fatal("/config/timeout should be reachable")
	}
}

// TestIsReachableAfterDelete checks the direct case: a node just removed
// by Delete is no longer reachable.
func TestIsReachableAfterDelete(t *testing.T) {
	tr := demoTree()
	config, err := tr.FindOne("/config")
	if err != nil {
		t.Fatal(err)
	}
	timeout := config.Children[0]
	if _, err := tr.Delete([]string{"/config/timeout"}); err != nil {
		t.Fatal(err)
	}
	if tr.IsReachable(timeout) {
		t.Fatal("deleted node should no longer be reachable")
	}
}

// TestIsReachableAfterAncestorDelete checks the indirect case this was
// actually built for: a node whose ANCESTOR was deleted (not the node
// itself) must also read as unreachable, even though its own .Parent
// field still points at the (now-detached) ancestor -- see removeChild,
// which never clears a removed node's Parent field.
func TestIsReachableAfterAncestorDelete(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)
	parent, err := tr.CreateStaged(stagingRoot, "", "parent", wire.NoValue())
	if err != nil {
		t.Fatal(err)
	}
	child, err := tr.CreateStaged(stagingRoot, "/NewNodes/parent", "child", wire.NoValue())
	if err != nil {
		t.Fatal(err)
	}
	if !tr.IsReachable(child) {
		t.Fatal("child should be reachable before its ancestor is deleted")
	}

	if _, err := tr.Delete([]string{"/NewNodes/parent"}); err != nil {
		t.Fatal(err)
	}
	if child.Parent != parent {
		t.Fatalf("child.Parent = %+v, want unchanged (removeChild doesn't clear it)", child.Parent)
	}
	if tr.IsReachable(child) {
		t.Fatal("child should no longer be reachable once its ancestor was deleted, despite child.Parent still pointing at it")
	}
}

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
