// Package authz decides which operations an authenticated identity may
// perform on which node paths. It is pure policy logic: identity comes from
// the TLS layer (see internal/certs) and enforcement lives in internal/tree,
// which checks every node an operation actually touches -- request
// expressions are regexes, so authorizing the expression text itself would
// mean nothing.
//
// A node's path is "/" followed by its keys from the root joined by "/"
// (the root itself is "/"); rules are regexes matched against that string.
package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Op int

const (
	// OpRead: the node may be seen, and matched by value predicates.
	OpRead Op = iota
	// OpWrite: the node's value may be changed, its child list relinked, or
	// a staged subtree attached beneath it.
	OpWrite
	// OpDelete: the node may be removed (or dropped by a relink).
	OpDelete
)

func (o Op) String() string {
	switch o {
	case OpRead:
		return "read"
	case OpWrite:
		return "write"
	case OpDelete:
		return "delete"
	}
	return "unknown"
}

// Checker answers whether one authenticated session may perform op on the
// node at path. A nil Checker, wherever one is accepted, means "allow
// everything" (used by internal callers and tests, never by a client
// request).
type Checker interface {
	Allowed(op Op, path string) bool
}

type ruleSet struct {
	read, write, del []*regexp.Regexp
}

// Policy is a loaded access-control policy. The zero value is not usable;
// use Load or Parse. A nil *Policy means "open": no identity-based rules,
// only the built-in session protections in NewChecker.
type Policy struct {
	readOnly   []*regexp.Regexp
	identities map[string]*ruleSet
}

type fileFormat struct {
	ReadOnly   []string `json:"readOnly"`
	Identities map[string]struct {
		Read   []string `json:"read"`
		Write  []string `json:"write"`
		Delete []string `json:"delete"`
	} `json:"identities"`
}

func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func compileAll(pats []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("bad regexp %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Parse reads a JSON policy:
//
//	{
//	  "readOnly": ["^/interfaces/if(In|Out)"],           // nobody may write or delete these
//	  "identities": {
//	    "admin":   {"read": ["^/"], "write": ["^/config"], "delete": ["^/config"]},
//	    "monitor": {"read": ["^/"]},
//	    "*":       {"read": ["^/users"]}                   // applies to every identity
//	  }
//	}
//
// Anything not allowed is denied. write and delete rules imply read on the
// same paths: a node you may change but not see could not be targeted at
// all, since targets are resolved through what the identity can see.
func Parse(data []byte) (*Policy, error) {
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	p := &Policy{identities: map[string]*ruleSet{}}
	var err error
	if p.readOnly, err = compileAll(f.ReadOnly); err != nil {
		return nil, fmt.Errorf("readOnly: %w", err)
	}
	for id, r := range f.Identities {
		rs := &ruleSet{}
		if rs.read, err = compileAll(r.Read); err != nil {
			return nil, fmt.Errorf("identity %q read: %w", id, err)
		}
		if rs.write, err = compileAll(r.Write); err != nil {
			return nil, fmt.Errorf("identity %q write: %w", id, err)
		}
		if rs.del, err = compileAll(r.Delete); err != nil {
			return nil, fmt.Errorf("identity %q delete: %w", id, err)
		}
		p.identities[id] = rs
	}
	return p, nil
}

func anyMatch(res []*regexp.Regexp, path string) bool {
	for _, re := range res {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// NewChecker builds the Checker for one session. p may be nil (open mode:
// identity rules don't apply, only the built-in session protections do).
func (p *Policy) NewChecker(identity, sessionID string) Checker {
	return &checker{policy: p, identity: identity, ownSession: "Connection-ID=" + sessionID}
}

// NewChecker on a nil *Policy is the open-mode checker.
func NewOpenChecker(sessionID string) Checker {
	return (*Policy)(nil).NewChecker("anonymous", sessionID)
}

type checker struct {
	policy     *Policy
	identity   string
	ownSession string // the "Connection-ID=<id>" key of this session's own subtree
}

const sessionsPrefix = "/Sessions"

// Allowed applies, in order:
//  1. built-in session rules (see sessionRule), which no policy can loosen;
//  2. the policy's global readOnly list (denies write and delete);
//  3. the identity's own rules plus the "*" rules -- or, with no policy
//     loaded, allow.
func (c *checker) Allowed(op Op, path string) bool {
	if decided, ok := c.sessionRule(op, path); decided {
		return ok
	}
	if c.policy == nil {
		return true
	}
	if op != OpRead && anyMatch(c.policy.readOnly, path) {
		return false
	}
	for _, id := range []string{c.identity, "*"} {
		rs := c.policy.identities[id]
		if rs == nil {
			continue
		}
		switch op {
		case OpRead:
			if anyMatch(rs.read, path) || anyMatch(rs.write, path) || anyMatch(rs.del, path) {
				return true
			}
		case OpWrite:
			if anyMatch(rs.write, path) {
				return true
			}
		case OpDelete:
			if anyMatch(rs.del, path) {
				return true
			}
		}
	}
	return false
}

// sessionRule handles everything under /Sessions, which is server-managed
// state rather than configuration, so policy doesn't get a say:
//
//   - /Sessions itself is readable by everyone (it's how a client finds its
//     own session), never writable.
//   - another session's subtree is invisible and untouchable.
//   - this session's own root and its three container nodes (NewNodes,
//     Errors, QueryResults) are readable only: the server holds direct
//     pointers to them, so removing or rewriting one would strand it.
//   - beneath NewNodes: fully open (it's this session's private staging
//     area, see Create).
//   - beneath Errors and QueryResults: readable and deletable, not
//     writable -- the server owns their contents, but a client may clear
//     old errors, and deleting a query's own results node is how it's
//     cancelled.
//
// decided is false for paths outside /Sessions.
func (c *checker) sessionRule(op Op, path string) (decided, allowed bool) {
	if path != sessionsPrefix && !strings.HasPrefix(path, sessionsPrefix+"/") {
		return false, false
	}
	if path == sessionsPrefix {
		return true, op == OpRead
	}
	rest := path[len(sessionsPrefix)+1:] // "Connection-ID=<id>[/container[/...]]"
	parts := strings.SplitN(rest, "/", 3)
	if parts[0] != c.ownSession {
		return true, false
	}
	if len(parts) == 1 { // own session root
		return true, op == OpRead
	}
	container := parts[1]
	deeper := len(parts) == 3
	switch container {
	case "NewNodes":
		return true, deeper || op == OpRead
	case "Errors", "QueryResults":
		if !deeper {
			return true, op == OpRead
		}
		return true, op == OpRead || op == OpDelete
	default:
		return true, op == OpRead
	}
}
