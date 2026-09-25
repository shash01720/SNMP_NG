package tree

import (
	"errors"
	"testing"

	"github.com/shashi/snmp-ng/goimpl/internal/authz"
	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

func checkerFor(t *testing.T, policy string) authz.Checker {
	t.Helper()
	p, err := authz.Parse([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	return p.NewChecker("u", "s1")
}

func TestGetOmitsUnreadableAndPrunesDescendants(t *testing.T) {
	tr := demoTree()
	// Reads /config and /config/timeout, not /config/retries or /users.
	auth := checkerFor(t, `{"identities":{"u":{"read":["^/config$","^/config/timeout$"]}}}`)

	flat, resume, _, err := tr.GetFullAs("/users", auth)
	if err != nil || len(flat[resume:]) != 0 {
		t.Fatalf("unreadable /users should return nothing: %+v, %v", flat, err)
	}
	flat, resume, _, err = tr.GetFullAs("/config", auth)
	if err != nil {
		t.Fatal(err)
	}
	nodes := flat[resume:]
	if len(nodes) != 2 || nodes[0].Key != "config" || nodes[1].Key != "timeout" {
		t.Fatalf("want config+timeout only (retries pruned), got %+v", nodes)
	}
	if nodes[0].FirstChild.Offset != 1 || nodes[1].NextSibling.Offset != 0 {
		t.Fatalf("pointers must describe the pruned shape: %+v", nodes)
	}
}

// A readable node under an unreadable parent stays reachable: policies
// grant by full path.
func TestGetTraversesUnreadableParent(t *testing.T) {
	tr := demoTree()
	auth := checkerFor(t, `{"identities":{"u":{"read":["^/config/timeout$"]}}}`)
	nodes, _, _, err := tr.GetFullAs("/config/timeout", auth)
	if err != nil || len(nodes) != 1 || nodes[0].Key != "timeout" {
		t.Fatalf("got %+v, %v", nodes, err)
	}
}

// A value predicate must not be usable as an oracle on data the caller
// can't read.
func TestValuePredicateIsNotAnOracle(t *testing.T) {
	tr := demoTree()
	none := checkerFor(t, `{"identities":{"u":{"read":["^/users"]}}}`)
	flat, resume, _, _ := tr.GetFullAs("/config/timeout=30", none)
	if len(flat[resume:]) != 0 {
		t.Fatal("matched a value the caller can't read")
	}
	all := checkerFor(t, `{"identities":{"u":{"read":["^/"]}}}`)
	flat, resume, _, _ = tr.GetFullAs("/config/timeout=30", all)
	if len(flat[resume:]) != 1 {
		t.Fatal("control: a reader should match it")
	}
	// Same through a parent segment's value predicate.
	flat, resume, _, _ = tr.GetFullAs("/users/user=alice", none)
	if len(flat[resume:]) != 1 {
		t.Fatal("control: readable /users/user=alice should match")
	}
}

func TestSetDeniedIsAtomicAndSentinel(t *testing.T) {
	tr := demoTree()
	auth := checkerFor(t, `{"identities":{"u":{"read":["^/"],"write":["^/config/timeout$"]}}}`)
	a, b := wire.StringValue("1"), wire.StringValue("2")
	_, err := tr.SetAs(&wire.Set{Edits: []wire.SetEdit{
		{Target: "/config/timeout", NewValue: &a}, // allowed
		{Target: "/config/retries", NewValue: &b}, // denied
	}}, nil, auth)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if got, _ := tr.Get("/config/timeout=30"); len(got) != 1 {
		t.Fatal("the permitted edit must not have been applied when another edit was denied")
	}
	// Control: only the permitted edit succeeds.
	if _, err := tr.SetAs(&wire.Set{Edits: []wire.SetEdit{{Target: "/config/timeout", NewValue: &a}}}, nil, auth); err != nil {
		t.Fatal(err)
	}
}

func TestSetCannotTargetUnreadableNode(t *testing.T) {
	tr := demoTree()
	auth := checkerFor(t, `{"identities":{"u":{"read":["^/users"],"write":["^/config"]}}}`)
	v := wire.StringValue("x")
	touched, err := tr.SetAs(&wire.Set{Edits: []wire.SetEdit{{Target: "/config/timeout", NewValue: &v}}}, nil, auth)
	if err != nil || len(touched) != 1 {
		t.Fatalf("write implies read, so this is allowed: %v, %v", touched, err)
	}
	none := checkerFor(t, `{"identities":{"u":{"read":["^/users"]}}}`)
	touched, err = tr.SetAs(&wire.Set{Edits: []wire.SetEdit{{Target: "/config/timeout", NewValue: &v}}}, nil, none)
	if err != nil || len(touched) != 0 {
		t.Fatalf("an unreadable target must look like no match (no oracle): %v, %v", touched, err)
	}
}

func TestDeleteRequiresDeleteOnWholeSubtree(t *testing.T) {
	tr := demoTree()
	// May delete the "users" containers themselves but not their children.
	shallow := checkerFor(t, `{"identities":{"u":{"read":["^/"],"delete":["^/users$"]}}}`)
	_, err := tr.DeleteAs([]string{"/users"}, shallow)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
	if got, _ := tr.Get("/users"); len(got) != 9 {
		t.Fatal("nothing may be removed after a denied delete")
	}
	deep := checkerFor(t, `{"identities":{"u":{"read":["^/"],"delete":["^/users"]}}}`)
	deleted, err := tr.DeleteAs([]string{"/users"}, deep)
	if err != nil || len(deleted) != 3 {
		t.Fatalf("deleted %v, err %v", deleted, err)
	}
}

// Delete-by-relink drops nodes too, so it needs delete permission on them.
func TestRelinkNeedsDeleteOnDroppedNodes(t *testing.T) {
	tr := demoTree()
	auth := checkerFor(t, `{"identities":{"u":{"read":["^/"],"write":["^/config/timeout$"]}}}`)
	none := wire.NonePointer()
	_, err := tr.SetAs(&wire.Set{Edits: []wire.SetEdit{{Target: "/config/timeout", NewNextSibling: &none}}}, nil, auth)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v: dropping /config/retries needs delete on it", err)
	}
	if got, _ := tr.Get("/config/retries"); len(got) != 1 {
		t.Fatal("retries must survive the denied relink")
	}
	allowed := checkerFor(t, `{"identities":{"u":{"read":["^/"],"write":["^/config/timeout$"],"delete":["^/config/retries$"]}}}`)
	if _, err := tr.SetAs(&wire.Set{Edits: []wire.SetEdit{{Target: "/config/timeout", NewNextSibling: &none}}}, nil, allowed); err != nil {
		t.Fatal(err)
	}
}

func TestNewParentNeedsWriteOnDestination(t *testing.T) {
	tr := demoTree()
	stagingRoot := &Node{Key: "NewNodes"}
	AppendChild(tr.Root, stagingRoot)
	if _, err := tr.CreateStaged(stagingRoot, "", "iface", wire.NoValue()); err != nil {
		t.Fatal(err)
	}
	dest := "/config"
	edit := []wire.SetEdit{{Target: "/NewNodes/iface", NewParent: &dest}}

	// (Test policy treats /NewNodes like any other path; in a real session
	// the built-in staging rule opens it.)
	noWrite := checkerFor(t, `{"identities":{"u":{"read":["^/"],"write":["^/NewNodes"]}}}`)
	if _, err := tr.SetAs(&wire.Set{Edits: edit}, stagingRoot, noWrite); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("err = %v, want denial: no write on /config", err)
	}
	if got, _ := tr.Get("/NewNodes/iface"); len(got) != 1 {
		t.Fatal("the staged node must stay staged after a denied attach")
	}
	ok := checkerFor(t, `{"identities":{"u":{"read":["^/"],"write":["^/NewNodes","^/config"]}}}`)
	if _, err := tr.SetAs(&wire.Set{Edits: edit}, stagingRoot, ok); err != nil {
		t.Fatal(err)
	}
}

func TestFindAllAsFiltersQuerySampling(t *testing.T) {
	tr := demoTree()
	auth := checkerFor(t, `{"identities":{"u":{"read":["^/config/timeout$"]}}}`)
	got, err := tr.FindAllAs("/config/.*", auth)
	if err != nil || len(got) != 1 || got[0].Key != "timeout" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
