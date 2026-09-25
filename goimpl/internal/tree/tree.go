// Package tree is the in-memory Node tree: construction, the NodePointer
// match-expression parser/evaluator, and flattening a match into wire.Node
// values with offset pointers.
package tree

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

// Node is a tree node with real child pointers (unlike wire.Node, which
// only carries offset/absolute pointers for the wire).
type Node struct {
	Key      string
	Value    wire.NodeValue
	Children []*Node
	Parent   *Node
}

// Tree is a Node tree guarded by a single mutex -- simple and sufficient
// for this reference implementation's traffic volumes; a real deployment
// with heavy concurrent Query/Set traffic would want finer-grained locking.
type Tree struct {
	mu   sync.RWMutex
	Root *Node

	// changeMu/changeGen/changeCh implement a lightweight broadcast used by
	// Query's onChange collection mode (see ChangedSince) so it can block
	// until the next mutation instead of polling on a timer. changeGen is a
	// monotonically increasing counter, bumped by notifyChanged on every
	// Set/AppendUnder; changeCh is closed (and replaced) at the same time,
	// waking anyone currently blocked on it. Tracking the generation
	// alongside the channel, rather than relying on the channel alone, is
	// what makes ChangedSince race-free: a caller that was busy handling
	// one notification and only gets back around to calling ChangedSince
	// after a second mutation already happened still sees "already stale"
	// (since != current generation) and is woken immediately, instead of
	// blocking on a fresh channel and missing that second mutation
	// entirely until some third one happens to occur.
	changeMu  sync.Mutex
	changeGen uint64
	changeCh  chan struct{}
}

func New() *Tree {
	return &Tree{Root: &Node{Key: "/", Value: wire.NoValue()}, changeCh: make(chan struct{})}
}

// ChangedSince returns a channel that becomes ready once the tree has been
// mutated at least once since generation `since` -- immediately ready if
// that has already happened -- plus the generation to pass as `since` on
// the caller's next call. It never blocks itself; the caller selects on
// the returned channel (typically alongside a context/ticker channel).
func (t *Tree) ChangedSince(since uint64) (ch <-chan struct{}, gen uint64) {
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	if since != t.changeGen {
		already := make(chan struct{})
		close(already)
		return already, t.changeGen
	}
	return t.changeCh, t.changeGen
}

func (t *Tree) notifyChanged() {
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	close(t.changeCh)
	t.changeCh = make(chan struct{})
	t.changeGen++
}

// AppendChild adds `child` as parent's last child, fixing up Parent.
func AppendChild(parent, child *Node) {
	child.Parent = parent
	parent.Children = append(parent.Children, child)
}

// --- match-expression parsing ---
//
//	request    = expression ["@" resume-index]
//	expression = 1*( ["/"] key-regexp ["=" value-regexp] )
//
// "/" separates segments (a leading one is optional/ignored); "=" separates
// a segment's key regexp from its optional value regexp; "@" (at the very
// end) names a resume index. A literal "/", "=" or "@" inside a regexp is
// written "\/", "\=", "\@".

type Segment struct {
	KeyRe   *regexp.Regexp
	ValueRe *regexp.Regexp // nil if this segment has no value predicate
}

func ParseExpression(expression string) ([]Segment, error) {
	var segments []Segment
	for _, part := range splitUnescaped(expression, '/') {
		if part == "" {
			continue
		}
		keyRaw, hasValue, valueRaw := splitFirstUnescaped(part, '=')
		keyRe, err := regexp.Compile("^(?:" + keyRaw + ")$")
		if err != nil {
			return nil, fmt.Errorf("bad key regexp %q: %w", keyRaw, err)
		}
		var valueRe *regexp.Regexp
		if hasValue {
			valueRe, err = regexp.Compile("^(?:" + valueRaw + ")$")
			if err != nil {
				return nil, fmt.Errorf("bad value regexp %q: %w", valueRaw, err)
			}
		}
		segments = append(segments, Segment{KeyRe: keyRe, ValueRe: valueRe})
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("empty NodePointer expression")
	}
	return segments, nil
}

// SplitResumeSuffix splits "expression@index" into (expression, index); a
// missing or non-numeric suffix yields (raw, 0).
func SplitResumeSuffix(raw string) (string, int) {
	before, found, after := splitFirstUnescaped(raw, '@')
	if found {
		if n, err := strconv.Atoi(after); err == nil {
			return before, n
		}
	}
	return raw, 0
}

func splitUnescaped(s string, delim byte) []string {
	var parts []string
	var buf strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) && (s[i+1] == delim || s[i+1] == '\\') {
			buf.WriteByte(s[i+1])
			i += 2
			continue
		}
		if c == delim {
			parts = append(parts, buf.String())
			buf.Reset()
			i++
			continue
		}
		buf.WriteByte(c)
		i++
	}
	parts = append(parts, buf.String())
	return parts
}

func splitFirstUnescaped(s string, delim byte) (before string, found bool, after string) {
	var buf strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) && (s[i+1] == delim || s[i+1] == '\\') {
			buf.WriteByte(s[i+1])
			i += 2
			continue
		}
		if c == delim {
			return buf.String(), true, s[i+1:]
		}
		buf.WriteByte(c)
		i++
	}
	return buf.String(), false, ""
}

// --- evaluation --------------------------------------------------------

// Evaluate walks root's children matching each segment in turn, returning
// the nodes matched by the final segment. Caller must hold at least a read
// lock on the owning Tree.
func Evaluate(root *Node, segments []Segment) []*Node {
	current := []*Node{root}
	for _, seg := range segments {
		var next []*Node
		for _, node := range current {
			for _, child := range node.Children {
				if !seg.KeyRe.MatchString(child.Key) {
					continue
				}
				if seg.ValueRe != nil {
					if !child.Value.Kind.IsNumeric() && child.Value.Kind != wire.ValueOctetString {
						continue
					}
					if !seg.ValueRe.MatchString(valueAsText(child.Value)) {
						continue
					}
				}
				next = append(next, child)
			}
		}
		current = next
	}
	return current
}

// EvaluateExactlyOne is a convenience for Set's target resolution, which
// must resolve to exactly one node.
func EvaluateExactlyOne(root *Node, segments []Segment) (*Node, error) {
	matches := Evaluate(root, segments)
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no node matched")
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("expression matched %d nodes, expected exactly 1", len(matches))
	}
}

func valueAsText(v wire.NodeValue) string {
	switch v.Kind {
	case wire.ValueOctetString:
		return string(v.OctetString)
	case wire.ValueInteger32:
		return strconv.FormatInt(int64(v.Integer32), 10)
	case wire.ValueUnsigned32:
		return strconv.FormatUint(uint64(v.Unsigned32), 10)
	case wire.ValueCounter32:
		return strconv.FormatUint(uint64(v.Counter32), 10)
	case wire.ValueCounter64:
		return strconv.FormatUint(v.Counter64, 10)
	case wire.ValueTimeTicks:
		return strconv.FormatUint(uint64(v.TimeTicks), 10)
	case wire.ValueReal:
		return strconv.FormatFloat(v.Real, 'g', -1, 64)
	default:
		return ""
	}
}

// --- flattening into wire.Node with offset pointers ---------------------
//
// Each matched node's whole subtree is flattened pre-order; multiple
// top-level matches are then chained to each other via nextSibling (even
// though they usually aren't real tree-siblings), so a later match that
// doesn't fit a size budget still gets a continuation instead of silently
// vanishing.

func FlattenMatches(matches []*Node) []wire.Node {
	var out []wire.Node
	var blockStarts []int
	for _, m := range matches {
		blockStarts = append(blockStarts, len(out))
		out = append(out, flattenSubtree(m)...)
	}
	for i := 0; i < len(blockStarts)-1; i++ {
		rootIdx := blockStarts[i]
		nextRootIdx := blockStarts[i+1]
		out[rootIdx].NextSibling = wire.OffsetPointer(int64(nextRootIdx - rootIdx))
	}
	return out
}

func flattenSubtree(root *Node) []wire.Node {
	var order []*Node
	parentOf := map[*Node]*Node{}
	siblingIndex := map[*Node]int{}

	var visit func(n, parent *Node)
	visit = func(n, parent *Node) {
		order = append(order, n)
		parentOf[n] = parent
		for i, c := range n.Children {
			siblingIndex[c] = i
		}
		for _, c := range n.Children {
			visit(c, n)
		}
	}
	visit(root, nil)

	indexOf := map[*Node]int{}
	for i, n := range order {
		indexOf[n] = i
	}

	wireNodes := make([]wire.Node, len(order))
	for i, n := range order {
		firstChild := wire.OffsetPointer(0)
		if len(n.Children) > 0 {
			firstChild = wire.OffsetPointer(int64(indexOf[n.Children[0]] - i))
		}
		nextSibling := wire.OffsetPointer(0)
		if parent := parentOf[n]; parent != nil {
			pos := siblingIndex[n]
			if pos+1 < len(parent.Children) {
				nextSibling = wire.OffsetPointer(int64(indexOf[parent.Children[pos+1]] - i))
			}
		}
		wireNodes[i] = wire.Node{Key: n.Key, Value: n.Value, FirstChild: firstChild, NextSibling: nextSibling}
	}
	return wireNodes
}

// --- Tree-level convenience wrappers (locking) ----------------------------

func (t *Tree) Get(expression string) ([]wire.Node, error) {
	flat, resume, _, err := t.GetFull(expression)
	if err != nil {
		return nil, err
	}
	return flat[resume:], nil
}

// GetFull evaluates `expression` and returns its FULL deterministic
// flattened result (from index 0 -- the same array regardless of any
// "@resume" suffix on expression), the resume index to start delivering
// from, and the base expression (with any "@resume" suffix stripped) to
// use when generating "<base>@<index>" continuation pointers.
//
// Callers that need to fit a limited number of nodes into one message
// (e.g. one QUIC datagram) use this plus FitToSize instead of Get, which
// always returns the complete remainder.
func (t *Tree) GetFull(expression string) (flat []wire.Node, resumeIndex int, base string, err error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	base, resumeIndex = SplitResumeSuffix(expression)
	segments, err := ParseExpression(base)
	if err != nil {
		return nil, 0, "", err
	}
	matches := Evaluate(t.Root, segments)
	flat = FlattenMatches(matches)
	if resumeIndex < 0 || resumeIndex > len(flat) {
		return nil, 0, "", fmt.Errorf("resume index %d out of range for %d node(s)", resumeIndex, len(flat))
	}
	return flat, resumeIndex, base, nil
}

// FitToSize returns the largest prefix of flat[resumeIndex:] (with any
// offset pointer that would reach past the cut rewritten to an absolute
// "<baseExpression>@<index>" continuation pointer) such that
// measure(prefix) <= maxSize. measure should return the byte size of
// whatever message envelope the caller will actually send containing that
// prefix as its nodes (e.g. a whole marshaled NodeTreeMessage{Response{...}}).
// truncated reports whether the full remainder didn't fit (i.e. whether a
// continuation pointer had to be generated).
//
// Offsets are deltas (target index - current index), so they stay valid wherever a
// contiguous run of them ends up, but a node included in the window can
// point past it -- exactly the case this rewrites.
func FitToSize(flat []wire.Node, resumeIndex int, baseExpression string, maxSize int, measure func([]wire.Node) int) (window []wire.Node, truncated bool) {
	windowTotal := len(flat) - resumeIndex
	for n := windowTotal; n > 0; n-- {
		candidate := fixupWindow(flat, resumeIndex, n, baseExpression)
		if measure(candidate) <= maxSize {
			return candidate, n < windowTotal
		}
	}
	return nil, windowTotal > 0
}

// fixupWindow copies flat[resumeIndex:resumeIndex+n] and rewrites any
// firstChild/nextSibling offset pointer that would land at or past the
// window's end into an absolute continuation pointer instead.
func fixupWindow(flat []wire.Node, resumeIndex, n int, baseExpression string) []wire.Node {
	endGlobal := resumeIndex + n
	included := make([]wire.Node, n)
	copy(included, flat[resumeIndex:endGlobal]) // value copy: safe to mutate included[i] without touching flat

	for j := range included {
		iGlobal := resumeIndex + j
		for _, field := range []*wire.NodePointer{&included[j].FirstChild, &included[j].NextSibling} {
			if field.Kind != wire.PointerOffset || field.Offset == 0 {
				continue // not a pointer, or the "none" sentinel
			}
			targetGlobal := iGlobal + int(field.Offset)
			if targetGlobal >= endGlobal {
				*field = wire.AbsolutePointer(fmt.Sprintf("%s@%d", baseExpression, targetGlobal))
			}
		}
	}
	return included
}

// FindOne resolves `expression` to exactly one live tree Node (for Set's
// target). Does not accept a resume ("@index") suffix -- that's a Get/Query
// pagination concept, not meaningful for identifying a single node to
// mutate.
func (t *Tree) FindOne(expression string) (*Node, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	segments, err := ParseExpression(expression)
	if err != nil {
		return nil, err
	}
	return EvaluateExactlyOne(t.Root, segments)
}

// FindAll resolves `expression` to every currently-matching live tree Node
// (for Query's sampling, which reads the same expression repeatedly).
func (t *Tree) FindAll(expression string) ([]*Node, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	segments, err := ParseExpression(expression)
	if err != nil {
		return nil, err
	}
	return Evaluate(t.Root, segments), nil
}

// IsReachable reports whether node is still part of the live tree (Root
// itself, or a descendant of it). A node detached by Delete or by Set's
// newFirstChild/newNextSibling/newParent keeps its own Parent field
// pointing at its old parent -- nothing clears it, see removeChild/
// relinkFirstChild/relinkNextSibling -- so merely walking the Parent
// chain up to Root proves nothing: a detached subtree's internal Parent
// pointers still lead there. What actually distinguishes "still attached"
// from "was cut loose" is whether each node in that chain is still
// present in its claimed parent's own Children slice; a node one level
// up the chain being missing from ITS parent's Children (not node's own)
// is exactly the "ancestor got deleted" case this exists to catch.
func (t *Tree) IsReachable(node *Node) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for n := node; n != t.Root; n = n.Parent {
		if n.Parent == nil || indexOfChild(n.Parent, n) < 0 {
			return false
		}
	}
	return true
}

// EnsurePath walks (creating as needed) a chain of container nodes
// key1/key2/... under the tree root, returning the final node. Used to
// materialize the "/Sessions/Connection-ID=<id>/..." virtual subtrees.
// Each path element is matched/created literally (not as a regexp).
func (t *Tree) EnsurePath(keys ...string) *Node {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ensurePathLocked(t.Root, keys)
}

// EnsurePath0 is EnsurePath starting from an already-resolved node
// (typically one returned by an earlier EnsurePath/EnsurePath0 call)
// instead of the tree root.
func (t *Tree) EnsurePath0(start *Node, keys ...string) *Node {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ensurePathLocked(start, keys)
}

func (t *Tree) ensurePathLocked(start *Node, keys []string) *Node {
	cur := start
	for _, key := range keys {
		var found *Node
		for _, c := range cur.Children {
			if c.Key == key {
				found = c
				break
			}
		}
		if found == nil {
			found = &Node{Key: key, Value: wire.NoValue()}
			AppendChild(cur, found)
		}
		cur = found
	}
	return cur
}

// AppendUnder appends a new child node under `parent` (already resolved via
// EnsurePath/FindOne), returning it. Used by Create and by error/query-
// result node generation.
func (t *Tree) AppendUnder(parent *Node, key string, value wire.NodeValue) *Node {
	t.mu.Lock()
	n := &Node{Key: key, Value: value}
	AppendChild(parent, n)
	t.mu.Unlock()
	t.notifyChanged()
	return n
}

// CreateStaged implements Create's node.asn semantics: parentExpr, if
// non-empty, must resolve to exactly one node that is stagingRoot itself
// or one of its own descendants (an error otherwise); an empty parentExpr
// appends directly under stagingRoot, matching the old single-parent
// behavior. This is how a client builds an arbitrarily deep subtree
// entirely under its own session's staged NewNodes, one Create call at a
// time, before attaching it to live config with Set's newParent.
func (t *Tree) CreateStaged(stagingRoot *Node, parentExpr string, key string, value wire.NodeValue) (*Node, error) {
	t.mu.Lock()
	parent := stagingRoot
	if parentExpr != "" {
		n, err := t.resolveExpressionExactlyOneLocked(parentExpr)
		if err != nil {
			t.mu.Unlock()
			return nil, fmt.Errorf("parent %q: %w", parentExpr, err)
		}
		if !isDescendantOrSelf(stagingRoot, n) {
			t.mu.Unlock()
			return nil, fmt.Errorf("parent %q: not part of this session's own staged nodes", parentExpr)
		}
		parent = n
	}
	n := &Node{Key: key, Value: value}
	AppendChild(parent, n)
	t.mu.Unlock()
	t.notifyChanged()
	return n, nil
}

// setEditPlan is one edit fully resolved against the tree as it stood
// before any edit in this Set request was applied -- see Set's doc comment
// for why resolving everything up front, before mutating anything, is what
// makes the whole request atomic.
type setEditPlan struct {
	edit        wire.SetEdit
	targets     []*Node // newValue's target(s) (0+); structural edits' single target (exactly 1, checked during planning)
	firstChild  *Node   // pre-resolved edit.NewFirstChild target; meaningful only if edit.NewFirstChild != nil (nil there means "clear")
	nextSibling *Node   // pre-resolved edit.NewNextSibling target; meaningful only if edit.NewNextSibling != nil
	newParent   *Node   // pre-resolved edit.NewParent target; meaningful only if edit.NewParent != nil
}

// Set applies every edit in s.Edits atomically. Each edit's target is a
// match expression (like Get's, not a NodePointer) which may match zero or
// more nodes for a value-only edit; newValue is applied to every match (a
// no-op if there are none, the same "empty match isn't an error" idempotent
// stance Get and Delete take). newFirstChild/newNextSibling/newParent are
// structural operations and require target to resolve to exactly one node.
//
// stagingRoot is this session's own NewNodes node (see Create), needed to
// enforce newParent's "target must currently be staged" rule; pass nil if
// the caller has no session concept (e.g. a test operating on the tree
// directly) and no edit in s.Edits uses newParent.
//
// Every edit's target -- and, for structural edits, its newFirstChild/
// newNextSibling/newParent pointer target -- is resolved against the tree
// as it stood when Set was called, before any edit in this request is
// applied, so earlier edits never change what a later edit's target
// matches. If any edit fails to resolve, no mutation happens at all. If a
// later edit's planned relink turns out to conflict with an earlier
// edit's already-applied one (both touching the same parent's child list,
// possible only between two structural edits in the same request), every
// mutation already applied in this call is rolled back and the conflict
// is reported as an error: the request is genuinely all-or-nothing, not
// best-effort.
//
// Returns every node actually written to (deduplicated, first-touched
// order) for the caller to report back to the client.
func (t *Tree) Set(s *wire.Set, stagingRoot *Node) ([]*Node, error) {
	t.mu.Lock()

	var plans []setEditPlan
	for _, edit := range s.Edits {
		segments, err := ParseExpression(edit.Target)
		if err != nil {
			t.mu.Unlock()
			return nil, fmt.Errorf("target %q: %w", edit.Target, err)
		}
		targets := Evaluate(t.Root, segments)
		structural := edit.NewFirstChild != nil || edit.NewNextSibling != nil || edit.NewParent != nil
		if structural && len(targets) != 1 {
			t.mu.Unlock()
			return nil, fmt.Errorf("target %q: newFirstChild/newNextSibling/newParent require exactly 1 match, got %d", edit.Target, len(targets))
		}
		plan := setEditPlan{edit: edit, targets: targets}
		if edit.NewFirstChild != nil {
			n, err := t.resolvePointerAsChildLocked(*edit.NewFirstChild)
			if err != nil {
				t.mu.Unlock()
				return nil, fmt.Errorf("target %q: newFirstChild: %w", edit.Target, err)
			}
			plan.firstChild = n
		}
		if edit.NewNextSibling != nil {
			n, err := t.resolvePointerAsChildLocked(*edit.NewNextSibling)
			if err != nil {
				t.mu.Unlock()
				return nil, fmt.Errorf("target %q: newNextSibling: %w", edit.Target, err)
			}
			plan.nextSibling = n
		}
		if edit.NewParent != nil {
			if stagingRoot == nil || !isDescendant(stagingRoot, targets[0]) {
				t.mu.Unlock()
				return nil, fmt.Errorf("target %q: newParent: target is not one of this session's own staged nodes", edit.Target)
			}
			newParentNode, err := t.resolveExpressionExactlyOneLocked(*edit.NewParent)
			if err != nil {
				t.mu.Unlock()
				return nil, fmt.Errorf("target %q: newParent: %w", edit.Target, err)
			}
			if newParentNode == targets[0] || isDescendant(targets[0], newParentNode) {
				t.mu.Unlock()
				return nil, fmt.Errorf("target %q: newParent: would create a cycle", edit.Target)
			}
			plan.newParent = newParentNode
		}
		plans = append(plans, plan)
	}

	touched, err := applySetPlans(plans)
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if len(touched) > 0 {
		t.notifyChanged()
	}
	return touched, nil
}

// applySetPlans mutates the tree per plans, rolling back every change made
// in this call if any structural relink fails partway through (see Set's
// doc comment). Caller must hold t.mu.
func applySetPlans(plans []setEditPlan) (touched []*Node, err error) {
	type valueUndo struct {
		node *Node
		old  wire.NodeValue
	}
	type parentUndo struct {
		node *Node
		old  *Node
	}
	var valueUndos []valueUndo
	var parentUndos []parentUndo
	childrenUndos := map[*Node][]*Node{}
	snapshotChildren := func(n *Node) {
		if _, done := childrenUndos[n]; done {
			return
		}
		old := make([]*Node, len(n.Children))
		copy(old, n.Children)
		childrenUndos[n] = old
	}
	rollback := func() {
		for _, u := range valueUndos {
			u.node.Value = u.old
		}
		for _, u := range parentUndos {
			u.node.Parent = u.old
		}
		for n, old := range childrenUndos {
			n.Children = old
		}
	}

	seen := map[*Node]bool{}
	addTouched := func(n *Node) {
		if !seen[n] {
			seen[n] = true
			touched = append(touched, n)
		}
	}

	for _, p := range plans {
		if p.edit.NewValue != nil {
			for _, n := range p.targets {
				valueUndos = append(valueUndos, valueUndo{node: n, old: n.Value})
				n.Value = *p.edit.NewValue
				addTouched(n)
			}
		}
		if p.edit.NewFirstChild != nil {
			target := p.targets[0]
			snapshotChildren(target)
			if err := relinkFirstChild(target, p.firstChild); err != nil {
				rollback()
				return nil, fmt.Errorf("target %q: newFirstChild: %w", p.edit.Target, err)
			}
			addTouched(target)
		}
		if p.edit.NewNextSibling != nil {
			target := p.targets[0]
			if target.Parent != nil {
				snapshotChildren(target.Parent)
			}
			if err := relinkNextSibling(target, p.nextSibling); err != nil {
				rollback()
				return nil, fmt.Errorf("target %q: newNextSibling: %w", p.edit.Target, err)
			}
			addTouched(target)
		}
		if p.edit.NewParent != nil {
			target := p.targets[0]
			newParent := p.newParent
			oldParent := target.Parent
			if oldParent != nil {
				snapshotChildren(oldParent)
				if indexOfChild(oldParent, target) < 0 {
					rollback()
					return nil, fmt.Errorf("target %q: newParent: node is no longer where it was resolved (removed by an earlier edit in this request)", p.edit.Target)
				}
			}
			snapshotChildren(newParent)
			if oldParent != nil {
				removeChild(oldParent, target)
			}
			parentUndos = append(parentUndos, parentUndo{node: target, old: oldParent})
			target.Parent = newParent
			newParent.Children = append(newParent.Children, target)
			addTouched(target)
		}
	}
	return touched, nil
}

// Delete removes every node matched by any expression in targets from its
// parent's child list, computing whatever relink is needed itself -- the
// caller only needs to address the node it wants gone, not compute which
// sibling/parent pointer to relink around it (see node.asn's Delete docs).
// Every target is evaluated against the tree as it stood when Delete was
// called, exactly like Set. A target matching zero nodes is not an error
// (the same idempotent-delete stance a retried at-least-once request
// needs: deleting an already-gone node must not start failing).
//
// The tree root can never be a match -- Evaluate only ever matches a
// node's children, never the node it's handed, so there's no expression
// that resolves to the root itself.
//
// Returns every node actually deleted (its state just before removal,
// deduplicated, first-matched order) for the caller to report back to the
// client.
func (t *Tree) Delete(targets []string) ([]*Node, error) {
	t.mu.Lock()

	var matched []*Node
	seen := map[*Node]bool{}
	for _, expr := range targets {
		segments, err := ParseExpression(expr)
		if err != nil {
			t.mu.Unlock()
			return nil, fmt.Errorf("target %q: %w", expr, err)
		}
		for _, n := range Evaluate(t.Root, segments) {
			if !seen[n] {
				seen[n] = true
				matched = append(matched, n)
			}
		}
	}
	for _, n := range matched {
		removeChild(n.Parent, n)
	}
	t.mu.Unlock()

	if len(matched) > 0 {
		t.notifyChanged()
	}
	return matched, nil
}

// removeChild removes child from parent's Children slice. child must
// currently be one of parent's children.
func removeChild(parent, child *Node) {
	idx := indexOfChild(parent, child)
	parent.Children = append(parent.Children[:idx], parent.Children[idx+1:]...)
}

func (t *Tree) resolveOneLocked(p wire.NodePointer) (*Node, error) {
	if p.Kind != wire.PointerAbsolute {
		return nil, fmt.Errorf("must be an absolute expression, not an offset")
	}
	return t.resolveExpressionExactlyOneLocked(p.Absolute)
}

func (t *Tree) resolveExpressionExactlyOneLocked(expr string) (*Node, error) {
	segments, err := ParseExpression(expr)
	if err != nil {
		return nil, err
	}
	return EvaluateExactlyOne(t.Root, segments)
}

// isDescendant reports whether node is a strict descendant of root (root
// itself doesn't count -- see isDescendantOrSelf for that).
func isDescendant(root, node *Node) bool {
	for n := node.Parent; n != nil; n = n.Parent {
		if n == root {
			return true
		}
	}
	return false
}

func isDescendantOrSelf(root, node *Node) bool {
	return root == node || isDescendant(root, node)
}

// resolvePointerAsChildLocked resolves a NewFirstChild/NewNextSibling value:
// PointerNone means "detach" (nil), PointerAbsolute names the node to point
// to (which must be an existing sibling of the relevant list -- reparenting
// across parents is out of scope for this Set message, matching the
// "delete by relinking" use case node.asn documents, not general tree
// surgery).
func (t *Tree) resolvePointerAsChildLocked(p wire.NodePointer) (*Node, error) {
	if p.Kind == wire.PointerNone {
		return nil, nil
	}
	return t.resolveOneLocked(p)
}

func relinkFirstChild(parent, newFirstChild *Node) error {
	if newFirstChild == nil {
		parent.Children = nil
		return nil
	}
	if newFirstChild.Parent != parent {
		return fmt.Errorf("%q is not a child of the target node", newFirstChild.Key)
	}
	idx := indexOfChild(parent, newFirstChild)
	if idx < 0 {
		// newFirstChild.Parent still says parent (that field is never
		// updated when a node is spliced out of Children -- see
		// removeChild/relinkNextSibling), but it's no longer actually
		// among parent's children. Only reachable from a multi-edit Set
		// where an earlier edit in the same request already removed it;
		// a single edit resolved fresh against the live tree can't hit
		// this.
		return fmt.Errorf("%q is no longer among the target node's children (removed by an earlier edit in this request)", newFirstChild.Key)
	}
	parent.Children = parent.Children[idx:]
	return nil
}

func relinkNextSibling(node, newNextSibling *Node) error {
	parent := node.Parent
	if parent == nil {
		return fmt.Errorf("target node has no parent (it is the root)")
	}
	idx := indexOfChild(parent, node)
	if idx < 0 {
		return fmt.Errorf("target node is no longer among its parent's children (removed by an earlier edit in this request)")
	}
	if newNextSibling == nil {
		parent.Children = parent.Children[:idx+1]
		return nil
	}
	if newNextSibling.Parent != parent {
		return fmt.Errorf("%q is not a sibling of the target node", newNextSibling.Key)
	}
	newIdx := indexOfChild(parent, newNextSibling)
	if newIdx < 0 {
		return fmt.Errorf("%q is no longer among the target node's siblings (removed by an earlier edit in this request)", newNextSibling.Key)
	}
	parent.Children = append(parent.Children[:idx+1:idx+1], parent.Children[newIdx:]...)
	return nil
}

func indexOfChild(parent, child *Node) int {
	for i, c := range parent.Children {
		if c == child {
			return i
		}
	}
	return -1
}
