package authz

import "testing"

const testPolicy = `{
  "readOnly": ["^/interfaces/if(In|Out)"],
  "identities": {
    "admin":   {"read": ["^/"], "write": ["^/config", "^/interfaces"], "delete": ["^/config"]},
    "monitor": {"read": ["^/"]},
    "*":       {"read": ["^/users"]}
  }
}`

func mustPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIdentityRules(t *testing.T) {
	p := mustPolicy(t)
	admin := p.NewChecker("admin", "s1")
	monitor := p.NewChecker("monitor", "s1")
	stranger := p.NewChecker("nobody", "s1")

	cases := []struct {
		name string
		c    Checker
		op   Op
		path string
		want bool
	}{
		{"admin writes config", admin, OpWrite, "/config/timeout", true},
		{"admin deletes config", admin, OpDelete, "/config/timeout", true},
		{"admin can't delete users (no rule)", admin, OpDelete, "/users/user", false},
		{"monitor reads anything", monitor, OpRead, "/config/timeout", true},
		{"monitor can't write", monitor, OpWrite, "/config/timeout", false},
		{"monitor can't delete", monitor, OpDelete, "/config/timeout", false},
		{"stranger has only the * rules", stranger, OpRead, "/users/user", true},
		{"stranger denied elsewhere", stranger, OpRead, "/config/timeout", false},
		{"write implies read", admin, OpRead, "/interfaces/ifAdminStatus", true},
	}
	for _, c := range cases {
		if got := c.c.Allowed(c.op, c.path); got != c.want {
			t.Errorf("%s: Allowed(%v, %q) = %v, want %v", c.name, c.op, c.path, got, c.want)
		}
	}
}

// readOnly binds even an identity whose own write rule would otherwise
// allow the path.
func TestReadOnlyOverridesWriteRule(t *testing.T) {
	admin := mustPolicy(t).NewChecker("admin", "s1")
	if !admin.Allowed(OpWrite, "/interfaces/ifAdminStatus") {
		t.Error("ifAdminStatus should be writable")
	}
	if admin.Allowed(OpWrite, "/interfaces/ifInOctets") {
		t.Error("ifInOctets is readOnly and must not be writable, despite the write rule")
	}
	if admin.Allowed(OpDelete, "/interfaces/ifOutOctets") {
		t.Error("readOnly must block delete too")
	}
	if !admin.Allowed(OpRead, "/interfaces/ifInOctets") {
		t.Error("readOnly must not block reads")
	}
}

func TestSessionIsolationAndOwnContainers(t *testing.T) {
	// Even an identity with blanket rules can't touch another session, and
	// open mode (nil policy) enforces the same session rules.
	open := NewOpenChecker("mine")
	admin := mustPolicy(t).NewChecker("admin", "mine")
	for name, c := range map[string]Checker{"open": open, "admin": admin} {
		if c.Allowed(OpRead, "/Sessions/Connection-ID=other/Errors") {
			t.Errorf("%s: another session's subtree must be invisible", name)
		}
		if c.Allowed(OpDelete, "/Sessions/Connection-ID=other/QueryResults/Query-SequenceNumber=1") {
			t.Errorf("%s: another session's queries must not be cancellable", name)
		}
		if !c.Allowed(OpRead, "/Sessions") || c.Allowed(OpWrite, "/Sessions") {
			t.Errorf("%s: /Sessions is read-only", name)
		}
		if !c.Allowed(OpRead, "/Sessions/Connection-ID=mine") {
			t.Errorf("%s: own session root should be readable", name)
		}
		if !c.Allowed(OpWrite, "/Sessions/Connection-ID=mine/NewNodes/interface") ||
			!c.Allowed(OpDelete, "/Sessions/Connection-ID=mine/NewNodes/interface") {
			t.Errorf("%s: own staging area must be fully open", name)
		}
		if c.Allowed(OpDelete, "/Sessions/Connection-ID=mine/NewNodes") {
			t.Errorf("%s: the NewNodes container itself must be protected", name)
		}
		if !c.Allowed(OpDelete, "/Sessions/Connection-ID=mine/QueryResults/Query-SequenceNumber=2") {
			t.Errorf("%s: deleting a query's results node is how it's cancelled", name)
		}
		if c.Allowed(OpDelete, "/Sessions/Connection-ID=mine/QueryResults") {
			t.Errorf("%s: the QueryResults container itself must be protected", name)
		}
		if c.Allowed(OpWrite, "/Sessions/Connection-ID=mine/Errors/InvalidSet/message") {
			t.Errorf("%s: server-owned error contents must not be client-writable", name)
		}
	}
}

func TestOpenModeAllowsEverythingOutsideSessions(t *testing.T) {
	open := NewOpenChecker("s")
	for _, op := range []Op{OpRead, OpWrite, OpDelete} {
		if !open.Allowed(op, "/config/timeout") {
			t.Errorf("open mode should allow %v on /config/timeout", op)
		}
	}
}

func TestParseRejectsBadRegexp(t *testing.T) {
	if _, err := Parse([]byte(`{"readOnly": ["("]}`)); err == nil {
		t.Fatal("expected an error for an invalid regexp")
	}
	if _, err := Parse([]byte(`{"identities": {"a": {"write": ["["]}}}`)); err == nil {
		t.Fatal("expected an error for an invalid identity regexp")
	}
}
