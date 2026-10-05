package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/shash01720/SNMP_NG/goimpl/internal/authz"
	"github.com/shash01720/SNMP_NG/goimpl/internal/certs"
	"github.com/shash01720/SNMP_NG/goimpl/internal/reliability"
	"github.com/shash01720/SNMP_NG/goimpl/internal/tree"
	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

// These tests run a real Server on a loopback QUIC listener and drive it
// with a minimal client, so every message crosses the BER codec, the
// reliability layer and QUIC datagrams exactly as in production.

const waitFor = 3 * time.Second

func seed(s *Server) {
	t := s.Tree
	for _, u := range []struct{ user, group string }{{"alice", "admin"}, {"bob", "user"}} {
		n := t.AppendUnder(t.Root, "users", wire.NoValue())
		t.AppendUnder(n, "user", wire.StringValue(u.user))
		t.AppendUnder(n, "group", wire.StringValue(u.group))
	}
	config := t.AppendUnder(t.Root, "config", wire.NoValue())
	t.AppendUnder(config, "timeout", wire.Integer32Value(30))
	t.AppendUnder(config, "retries", wire.Integer32Value(3))
}

// startServer runs srv on an ephemeral loopback port until the test ends
// and returns its address.
func startServer(t *testing.T, srv *Server, tlsConf *tls.Config) string {
	t.Helper()
	if tlsConf == nil {
		var err error
		if tlsConf, err = certs.GenerateSelfSigned(); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		ln.Close()
		<-done
	})
	return ln.Addr().String()
}

type testClient struct {
	t        *testing.T
	conn     *quic.Conn
	sender   *reliability.Sender
	receiver *reliability.Receiver

	mu      sync.Mutex
	nextSeq int64
	replies map[int64]chan *wire.Response // by InReplyTo; pushes share their query's
}

func dial(t *testing.T, addr string, tlsConf *tls.Config) *testClient {
	t.Helper()
	if tlsConf == nil {
		tlsConf = certs.ClientConfig()
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{EnableDatagrams: true})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	c := &testClient{t: t, conn: conn, receiver: reliability.NewReceiver(), replies: make(map[int64]chan *wire.Response)}
	c.sender = reliability.NewSender(conn.SendDatagram, retransmitInterval, maxRetransmits, nil)
	go c.sender.RunRetransmitLoop(ctx)
	go c.readLoop(ctx)
	go c.ackLoop(ctx)
	t.Cleanup(func() {
		cancel()
		conn.CloseWithError(0, "")
	})
	return c
}

func (c *testClient) readLoop(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		msg, err := wire.UnmarshalMessage(data)
		if err != nil {
			continue
		}
		switch msg.Kind {
		case wire.MsgResponse:
			if c.receiver.MarkReceived(msg.Response.SequenceNumber) {
				c.channel(msg.Response.InReplyTo) <- msg.Response
			}
		case wire.MsgSummaryAck:
			c.sender.HandleAck(msg.SummaryAck)
		}
	}
}

func (c *testClient) ackLoop(ctx context.Context) {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ack := c.receiver.BuildAck(); len(ack.Received) > 0 {
				_ = c.conn.SendDatagram(wire.MarshalMessage(wire.Message{Kind: wire.MsgSummaryAck, SummaryAck: ack}))
			}
		}
	}
}

func (c *testClient) channel(inReplyTo int64) chan *wire.Response {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.replies[inReplyTo]
	if !ok {
		ch = make(chan *wire.Response, 64)
		c.replies[inReplyTo] = ch
	}
	return ch
}

func (c *testClient) allocSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextSeq++
	return c.nextSeq
}

// send transmits msg under seq without waiting for a reply.
func (c *testClient) send(seq int64, msg wire.Message) {
	c.t.Helper()
	if err := c.sender.Send(seq, wire.MarshalMessage(msg)); err != nil {
		c.t.Fatalf("send seq %d: %v", seq, err)
	}
}

// next returns the next Response replying to seq, failing the test after
// waitFor.
func (c *testClient) next(seq int64) *wire.Response {
	c.t.Helper()
	select {
	case r := <-c.channel(seq):
		return r
	case <-time.After(waitFor):
		c.t.Fatalf("no response to seq %d within %v", seq, waitFor)
		return nil
	}
}

// expectNone fails the test if anything replying to seq arrives within d.
func (c *testClient) expectNone(seq int64, d time.Duration) {
	c.t.Helper()
	select {
	case r := <-c.channel(seq):
		c.t.Fatalf("unexpected response to seq %d: %+v", seq, r.Nodes)
	case <-time.After(d):
	}
}

func (c *testClient) get(expr string) *wire.Response {
	c.t.Helper()
	seq := c.allocSeq()
	c.send(seq, wire.Message{Kind: wire.MsgGet, Get: &wire.Get{SequenceNumber: seq, Target: wire.AbsolutePointer(expr)}})
	return c.next(seq)
}

func (c *testClient) set(edits ...wire.SetEdit) *wire.Response {
	c.t.Helper()
	seq := c.allocSeq()
	c.send(seq, wire.Message{Kind: wire.MsgSet, Set: &wire.Set{SequenceNumber: seq, Edits: edits}})
	return c.next(seq)
}

func (c *testClient) setValue(expr string, v wire.NodeValue) *wire.Response {
	return c.set(wire.SetEdit{Target: expr, NewValue: &v})
}

func (c *testClient) del(targets ...string) *wire.Response {
	c.t.Helper()
	seq := c.allocSeq()
	c.send(seq, wire.Message{Kind: wire.MsgDelete, Delete: &wire.Delete{SequenceNumber: seq, Targets: targets}})
	return c.next(seq)
}

// sessionPath returns this connection's own /Sessions entry, escaped for
// use in an expression.
func (c *testClient) sessionPath() string {
	c.t.Helper()
	r := mustOK(c.t, c.get("/Sessions/Connection-ID.*"))
	if len(r.Nodes) == 0 {
		c.t.Fatalf("no session node")
	}
	return "/Sessions/" + strings.ReplaceAll(r.Nodes[0].Key, "=", `\=`)
}

func mustOK(t *testing.T, r *wire.Response) *wire.Response {
	t.Helper()
	if r.Error {
		ref := ""
		if r.ErrorNode != nil {
			ref = r.ErrorNode.Absolute
		}
		t.Fatalf("unexpected error response (see %s)", ref)
	}
	return r
}

// values returns the key=value pairs in r, in order, for comparison.
func values(r *wire.Response) []string {
	var out []string
	for _, n := range r.Nodes {
		out = append(out, n.Key+"="+valueString(n.Value))
	}
	return out
}

// pushShape checks that r is an untruncated Query push: a subtree rooted at a
// fixed-format timestamp node (no value, firstChild at the first leaf, no
// sibling), and returns that timestamp and the leaves as key=value strings.
func pushShape(t *testing.T, r *wire.Response) (time.Time, []string) {
	t.Helper()
	if len(r.Nodes) < 2 {
		t.Fatalf("push has %d node(s), want a timestamp root plus leaves: %v", len(r.Nodes), values(r))
	}
	root := r.Nodes[0]
	ts, err := time.Parse(timestampKeyFormat, root.Key)
	if err != nil {
		t.Fatalf("push root key %q is not a timestamp: %v", root.Key, err)
	}
	if root.Value.Kind != wire.ValueNoValue {
		t.Fatalf("timestamp root carries a value: %+v", root.Value)
	}
	if root.FirstChild.Kind != wire.PointerOffset || root.FirstChild.Offset != 1 {
		t.Fatalf("timestamp root firstChild = %+v, want offset 1", root.FirstChild)
	}
	if root.NextSibling.Kind != wire.PointerOffset || root.NextSibling.Offset != 0 {
		t.Fatalf("timestamp root nextSibling = %+v, want none", root.NextSibling)
	}
	return ts, values(&wire.Response{Nodes: r.Nodes[1:]})
}

// queryPush starts a query and returns its pushes (nodes only) in arrival
// order, discarding the empty registration ack. n is how many pushes to wait
// for; the ack is consumed alongside them.
func queryPush(t *testing.T, c *testClient, q *wire.Query, n int) (seq int64, pushes []*wire.Response) {
	t.Helper()
	seq = c.allocSeq()
	q.SequenceNumber = seq
	c.send(seq, wire.Message{Kind: wire.MsgQuery, Query: q})
	for acks := 0; len(pushes) < n || acks < 1; {
		r := mustOK(t, c.next(seq))
		if len(r.Nodes) == 0 {
			acks++
		} else {
			pushes = append(pushes, r)
		}
	}
	return seq, pushes
}

func escapedResultsPath(c *testClient, qseq int64) string {
	return c.sessionPath() + `/QueryResults/Query-SequenceNumber\=` + strconv.FormatInt(qseq, 10)
}

func valueString(v wire.NodeValue) string {
	switch v.Kind {
	case wire.ValueOctetString:
		return string(v.OctetString)
	case wire.ValueInteger32:
		return strconv.Itoa(int(v.Integer32))
	case wire.ValueNoValue:
		return ""
	default:
		return "?"
	}
}

func TestGetSetDeleteRoundTrip(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)

	if got := values(mustOK(t, c.get("/config/timeout"))); len(got) != 1 || got[0] != "timeout=30" {
		t.Fatalf("get timeout: %v", got)
	}

	// One Set, two targets, applied together.
	mustOK(t, c.set(
		wire.SetEdit{Target: "/config/timeout", NewValue: ptr(wire.Integer32Value(60))},
		wire.SetEdit{Target: "/config/retries", NewValue: ptr(wire.Integer32Value(5))},
	))
	if got := values(mustOK(t, c.get("/config"))); strings.Join(got, ",") != "config=,timeout=60,retries=5" {
		t.Fatalf("after set: %v", got)
	}

	mustOK(t, c.del("/config/retries"))
	if got := values(mustOK(t, c.get("/config"))); strings.Join(got, ",") != "config=,timeout=60" {
		t.Fatalf("after delete: %v", got)
	}
	// Deleting what's already gone is a no-op, not an error.
	mustOK(t, c.del("/config/retries"))

	if r := c.get("/config/[unterminated"); !r.Error {
		t.Fatalf("an invalid expression should produce an error response")
	}
}

// A request retransmitted after its response was lost must be answered from
// the cache, not executed twice: Create is not idempotent.
func TestDuplicateRequestAnsweredFromCache(t *testing.T) {
	srv := New()
	c := dial(t, startServer(t, srv, nil), nil)

	seq := c.allocSeq()
	msg := wire.Message{Kind: wire.MsgCreate, Create: &wire.Create{SequenceNumber: seq, Key: "note", Value: ptr(wire.StringValue("hi"))}}
	c.send(seq, msg)
	first := mustOK(t, c.next(seq))
	// Bypass the reliability layer to resend the identical datagram, as a
	// retransmit would.
	if err := c.conn.SendDatagram(wire.MarshalMessage(msg)); err != nil {
		t.Fatal(err)
	}
	second := mustOK(t, c.next(seq))
	if strings.Join(values(first), ",") != strings.Join(values(second), ",") {
		t.Fatalf("cached reply differs: %v vs %v", values(first), values(second))
	}

	staged := mustOK(t, c.get(c.sessionPath()+"/NewNodes/note"))
	if len(staged.Nodes) != 1 {
		t.Fatalf("duplicate Create ran twice: %d staged nodes", len(staged.Nodes))
	}
}

// A subtree built in the session's staging area is invisible until a Set
// with newParent moves it into live config.
func TestStagedCreateAndCommit(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)
	staging := c.sessionPath() + "/NewNodes"

	create := func(key string, value *wire.NodeValue, parent *string) {
		seq := c.allocSeq()
		c.send(seq, wire.Message{Kind: wire.MsgCreate, Create: &wire.Create{SequenceNumber: seq, Key: key, Value: value, Parent: parent}})
		mustOK(t, c.next(seq))
	}
	create("interface", nil, nil)
	create("ifDescr", ptr(wire.StringValue("eth9")), ptr(staging+"/interface"))

	if r := mustOK(t, c.get("/config/interface")); len(r.Nodes) != 0 {
		t.Fatalf("staged node visible in live config before commit")
	}
	mustOK(t, c.set(wire.SetEdit{Target: staging + "/interface", NewParent: ptr("/config")}))

	if got := values(mustOK(t, c.get("/config/interface"))); strings.Join(got, ",") != "interface=,ifDescr=eth9" {
		t.Fatalf("after commit: %v", got)
	}
	if r := mustOK(t, c.get(staging+"/interface")); len(r.Nodes) != 0 {
		t.Fatalf("commit should move the subtree, not copy it")
	}
}

// onChange pushes a baseline, then a push per real change, and stops once
// the query's own results node is deleted.
func TestOnChangeQueryAndCancelByDelete(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)

	qseq := c.allocSeq()
	c.send(qseq, wire.Message{Kind: wire.MsgQuery, Query: &wire.Query{
		SequenceNumber:   qseq,
		NodeExpression:   "/config/timeout",
		CollectionMode:   wire.OnChangeMode(),
		TransferInterval: 1,
	}})

	// The registration ack (no nodes) and the baseline push can arrive in
	// either order.
	var baseline []string
	for i := 0; i < 2; i++ {
		if r := mustOK(t, c.next(qseq)); len(r.Nodes) > 0 {
			_, baseline = pushShape(t, r)
		}
	}
	if strings.Join(baseline, ",") != "timeout=30" {
		t.Fatalf("baseline push: %v", baseline)
	}

	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	if _, got := pushShape(t, mustOK(t, c.next(qseq))); strings.Join(got, ",") != "timeout=99" {
		t.Fatalf("change push: %v", got)
	}

	// Setting the same value again is not a change.
	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	c.expectNone(qseq, 1500*time.Millisecond)

	mustOK(t, c.del(c.sessionPath()+"/QueryResults/Query-SequenceNumber.*"))
	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(7)))
	c.expectNone(qseq, 1500*time.Millisecond)
}

// Each transfer is a subtree rooted at its timestamp, and that exact subtree
// is also materialized under the query's results node in the session.
func TestQueryPushIsTimestampedSubtreeAlsoInSessionState(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)

	qseq, pushes := queryPush(t, c, &wire.Query{
		NodeExpression: "/config/.*",
		CollectionMode: wire.OnceMode(),
	}, 1)
	ts, leaves := pushShape(t, pushes[0])
	// Leaves are ordered by key, not by the (random) map order they were
	// collected in.
	if got := strings.Join(leaves, ","); got != "retries=3,timeout=30" {
		t.Fatalf("leaves = %s", got)
	}

	stored := mustOK(t, c.get(escapedResultsPath(c, qseq)+"/"+ts.Format(timestampKeyFormat)))
	if strings.Join(values(stored), ",") != strings.Join(values(pushes[0]), ",") {
		t.Fatalf("session state %v differs from what was pushed %v", values(stored), values(pushes[0]))
	}
}

// Successive pushes get strictly increasing timestamps and accumulate as
// sibling subtrees under the one results node.
func TestQueryPushTimestampsIncreaseAndAccumulate(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)

	qseq, first := queryPush(t, c, &wire.Query{
		NodeExpression:   "/config/timeout",
		CollectionMode:   wire.OnChangeMode(),
		TransferInterval: 1,
	}, 1)
	ts1, _ := pushShape(t, first[0])

	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	ts2, leaves := pushShape(t, mustOK(t, c.next(qseq)))
	if !ts2.After(ts1) {
		t.Fatalf("second push %v is not after first %v", ts2, ts1)
	}
	if strings.Join(leaves, ",") != "timeout=99" {
		t.Fatalf("second push leaves = %v", leaves)
	}

	// Both transfers are in session state: two timestamp roots, one leaf each.
	all := mustOK(t, c.get(escapedResultsPath(c, qseq)+"/.*"))
	if len(all.Nodes) != 4 {
		t.Fatalf("results node holds %d nodes, want 4 (two timestamp subtrees of 2): %v", len(all.Nodes), values(all))
	}
	if all.Nodes[0].Key != ts1.Format(timestampKeyFormat) || all.Nodes[2].Key != ts2.Format(timestampKeyFormat) {
		t.Fatalf("results node roots are %q and %q, want the two push timestamps", all.Nodes[0].Key, all.Nodes[2].Key)
	}
}

// A push too big for one datagram is cut with a continuation pointer into
// its materialized path, which a client Gets to reassemble it.
func TestQueryPushTruncatedAndReassembledByContinuation(t *testing.T) {
	srv := New()
	seed(srv)
	config, err := srv.Tree.FindOne("/config")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		srv.Tree.AppendUnder(config, fmt.Sprintf("k%02d", i), wire.Integer32Value(int32(i)))
	}
	// Roomy enough for a timestamp root, a few leaves and the continuation
	// pointer (a full path into session state, ~110 bytes), far short of all
	// 22 leaves.
	srv.MaxDatagramSizeOverride = 400
	c := dial(t, startServer(t, srv, nil), nil)

	q := &wire.Query{NodeExpression: "/config/.*", CollectionMode: wire.OnceMode()}
	_, pushes := queryPush(t, c, q, 1)

	got := map[int]wire.Node{}
	for i, n := range pushes[0].Nodes {
		got[i] = n
	}
	var pending []string
	collect := func(r *wire.Response) {
		for _, n := range r.Nodes {
			for _, p := range []wire.NodePointer{n.FirstChild, n.NextSibling} {
				if p.Kind == wire.PointerAbsolute {
					pending = append(pending, p.Absolute)
				}
			}
		}
	}
	collect(pushes[0])
	if len(pending) == 0 {
		t.Fatalf("the whole %d-node push fit in one 400-byte datagram; the test needs a bigger result", len(pushes[0].Nodes))
	}
	for steps := 0; len(pending) > 0 && steps < 20; steps++ {
		expr := pending[0]
		pending = pending[1:]
		base, idx := tree.SplitResumeSuffix(expr)
		if !strings.Contains(base, "/QueryResults/Query-SequenceNumber") {
			t.Fatalf("continuation %q doesn't point into the query's results", expr)
		}
		if _, done := got[idx]; done {
			continue
		}
		r := mustOK(t, c.get(expr))
		for i, n := range r.Nodes {
			got[idx+i] = n
		}
		collect(r)
	}

	// timestamp root + 20 filler leaves + retries + timeout, leaves by key.
	want := []string{"k00", "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09",
		"k10", "k11", "k12", "k13", "k14", "k15", "k16", "k17", "k18", "k19", "retries", "timeout"}
	if len(got) != 1+len(want) {
		t.Fatalf("reassembled %d nodes, want %d", len(got), 1+len(want))
	}
	if _, err := time.Parse(timestampKeyFormat, got[0].Key); err != nil {
		t.Fatalf("reassembled root %q is not a timestamp", got[0].Key)
	}
	for i, k := range want {
		if n, ok := got[i+1]; !ok || n.Key != k {
			t.Fatalf("reassembled index %d = %q, want %q", i+1, n.Key, k)
		}
	}
}

// A recurring query's pushes share inReplyTo with its registration ack, and
// arrive after it is cached; caching a push would replace that ack, so a
// retransmitted Query request would be answered with stale data instead.
// (A ONCE query can't show this: its push is sent before the ack is cached,
// so the ack overwrites it regardless.)
func TestQueryPushDoesNotReplaceCachedRegistrationAck(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)

	q := &wire.Query{NodeExpression: "/config/timeout", CollectionMode: wire.OnChangeMode(), TransferInterval: 1}
	qseq, _ := queryPush(t, c, q, 1)
	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	mustOK(t, c.next(qseq)) // the change push, sent after registration was cached

	// Resend the Query as a retransmit would (bypassing the reliability
	// layer's own dedup): the answer must still be the empty ack.
	if err := c.conn.SendDatagram(wire.MarshalMessage(wire.Message{Kind: wire.MsgQuery, Query: q})); err != nil {
		t.Fatal(err)
	}
	if again := mustOK(t, c.next(qseq)); len(again.Nodes) != 0 {
		t.Fatalf("a retransmitted Query got %d node(s) back (%v), want its empty ack", len(again.Nodes), values(again))
	}
}

// When not even one node plus its continuation pointer fits, the server must
// not answer with an empty success: that reads as "no match" and silently
// drops the data.
func TestGetThatCannotFitSendsNothingInsteadOfAnEmptySuccess(t *testing.T) {
	srv := New()
	seed(srv)
	srv.MaxDatagramSizeOverride = 20
	c := dial(t, startServer(t, srv, nil), nil)

	seq := c.allocSeq()
	c.send(seq, wire.Message{Kind: wire.MsgGet, Get: &wire.Get{SequenceNumber: seq, Target: wire.AbsolutePointer("/users")}})
	c.expectNone(seq, time.Second)
}

func TestNextTimestampIsStrictlyIncreasing(t *testing.T) {
	base := time.Now().Add(time.Hour)
	s := &sessionResultSink{lastTS: base}
	a, b := s.nextTimestamp(), s.nextTimestamp()
	if !a.Equal(base.Add(time.Nanosecond)) || !b.After(a) {
		t.Fatalf("clock behind the last timestamp must still yield increasing keys: %v then %v", a, b)
	}
	if a.Format(timestampKeyFormat) == b.Format(timestampKeyFormat) {
		t.Fatal("distinct timestamps formatted to the same key")
	}
}

func TestTimestampKeyIsFixedWidthAndExpressionSafe(t *testing.T) {
	for _, ts := range []time.Time{time.Unix(0, 0), time.Date(2026, 10, 5, 13, 0, 19, 5, time.UTC), time.Now()} {
		k := ts.UTC().Format(timestampKeyFormat)
		if len(k) != len(timestampKeyFormat) {
			t.Errorf("%q has length %d, want %d", k, len(k), len(timestampKeyFormat))
		}
		if strings.ContainsAny(k, `/=@\`) {
			t.Errorf("%q contains a character the expression grammar treats specially", k)
		}
	}
}

func TestSortedEntriesOrdersByKeyKeepingValueOrder(t *testing.T) {
	got := sortedEntries(map[string][]wire.NodeValue{
		"b": {wire.Integer32Value(1), wire.Integer32Value(2)},
		"a": {wire.Integer32Value(3)},
	})
	var order []string
	for _, e := range got {
		order = append(order, e.Key+"="+valueString(e.Value))
	}
	if strings.Join(order, ",") != "a=3,b=1,b=2" {
		t.Fatalf("got %v", order)
	}
}

// A query matching several nodes that share a key (here both users' "user")
// must not re-report them on every unrelated mutation, and must deliver only
// the one that really changed.
func TestOnChangeQueryOverNodesSharingAKey(t *testing.T) {
	srv := New()
	seed(srv)
	c := dial(t, startServer(t, srv, nil), nil)

	qseq, pushes := queryPush(t, c, &wire.Query{
		NodeExpression:   "/users/user",
		CollectionMode:   wire.OnChangeMode(),
		TransferInterval: 1,
	}, 1)
	if _, got := pushShape(t, pushes[0]); strings.Join(got, ",") != "user=alice,user=bob" {
		t.Fatalf("baseline leaves = %v, want both users", got)
	}

	// Wakes the query, changes nothing it watches.
	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	c.expectNone(qseq, 1500*time.Millisecond)

	mustOK(t, c.setValue("/users/user=alice", wire.StringValue("carol")))
	if _, got := pushShape(t, mustOK(t, c.next(qseq))); strings.Join(got, ",") != "user=carol" {
		t.Fatalf("change push = %v, want only the changed user", got)
	}
}

func TestGetTruncationContinuation(t *testing.T) {
	srv := New()
	seed(srv)
	srv.MaxDatagramSizeOverride = 60
	c := dial(t, startServer(t, srv, nil), nil)

	r := mustOK(t, c.get("/users"))
	var cont string
	for _, n := range r.Nodes {
		for _, p := range []wire.NodePointer{n.FirstChild, n.NextSibling} {
			if p.Kind == wire.PointerAbsolute && cont == "" {
				cont = p.Absolute
			}
		}
	}
	if !strings.HasPrefix(cont, "/users@") {
		t.Fatalf("expected a /users@<index> continuation pointer, got %q in %v", cont, values(r))
	}
	if next := mustOK(t, c.get(cont)); len(next.Nodes) == 0 {
		t.Fatalf("continuation %q returned nothing", cont)
	}
}

// With mutual TLS and a policy, the certificate's CommonName decides what a
// client may see and change.
func TestPolicyEnforcedByCertificateIdentity(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	caCert, caKey, err := certs.NewCA("test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write("ca.pem", caCert)
	issue := func(cn string, server bool) (string, string) {
		cert, key, err := certs.IssueCert(caCert, caKey, cn, server, []string{"localhost", "127.0.0.1"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return write(cn+".pem", cert), write(cn+"-key.pem", key)
	}
	srvCert, srvKey := issue("server", true)
	serverTLS, err := certs.ServerTLSConfig(srvCert, srvKey, caFile)
	if err != nil {
		t.Fatal(err)
	}

	srv := New()
	seed(srv)
	if srv.Policy, err = authz.Parse([]byte(`{
		"identities": {
			"admin":   {"read": ["^/"], "write": ["^/config"]},
			"monitor": {"read": ["^/config"]}
		}
	}`)); err != nil {
		t.Fatal(err)
	}
	addr := startServer(t, srv, serverTLS)

	connect := func(cn string) *testClient {
		cert, key := issue(cn, false)
		conf, err := certs.ClientTLSConfig(cert, key, caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		return dial(t, addr, conf)
	}
	admin, monitor := connect("admin"), connect("monitor")

	if got := values(mustOK(t, monitor.get("/users"))); len(got) != 0 {
		t.Fatalf("monitor should not see /users at all, got %v", got)
	}
	if got := values(mustOK(t, monitor.get("/config/timeout"))); strings.Join(got, ",") != "timeout=30" {
		t.Fatalf("monitor read of /config: %v", got)
	}
	if r := monitor.setValue("/config/timeout", wire.Integer32Value(1)); !r.Error {
		t.Fatalf("monitor write should be refused")
	}
	mustOK(t, admin.setValue("/config/timeout", wire.Integer32Value(45)))
	if got := values(mustOK(t, monitor.get("/config/timeout"))); strings.Join(got, ",") != "timeout=45" {
		t.Fatalf("monitor should see admin's write: %v", got)
	}
}

func ptr[T any](v T) *T { return &v }

// --- response cache expiry --------------------------------------------------

func newCacheOnlySession() *Session {
	return &Session{respCache: map[int64]cachedResponse{}}
}

func TestCacheExpiresEntriesOlderThanTTLInInsertionOrder(t *testing.T) {
	s := newCacheOnlySession()
	t0 := time.Unix(1000, 0)
	resp := &wire.Response{}
	s.cacheResponseAt(1, resp, t0)
	s.cacheResponseAt(2, resp, t0.Add(10*time.Second))
	s.cacheResponseAt(3, resp, t0.Add(respCacheTTL).Add(time.Second)) // entry 1 is now older than the TTL

	if _, ok := s.respCache[1]; ok {
		t.Error("entry 1 outlived the TTL")
	}
	if _, ok := s.respCache[2]; !ok {
		t.Error("entry 2 is within the TTL and must be kept")
	}
	if _, ok := s.respCache[3]; !ok {
		t.Error("the entry just inserted must be kept")
	}
}

// A sequence number cached a second time keeps its newer entry when the
// older insertion's record expires.
func TestCacheKeepsNewerEntryWhenSameSeqIsRecached(t *testing.T) {
	s := newCacheOnlySession()
	t0 := time.Unix(1000, 0)
	old, newer := &wire.Response{SequenceNumber: 1}, &wire.Response{SequenceNumber: 2}
	s.cacheResponseAt(7, old, t0)
	s.cacheResponseAt(7, newer, t0.Add(20*time.Second))
	s.cacheResponseAt(8, &wire.Response{}, t0.Add(respCacheTTL).Add(time.Second)) // expires the t0 record only

	got, ok := s.respCache[7]
	if !ok || got.resp != newer {
		t.Fatalf("seq 7 = %+v (present=%v), want the newer entry kept", got, ok)
	}
}

// Expiry must not cost time proportional to how many entries are held.
func TestCacheInsertIsConstantTimeWithManyEntriesHeld(t *testing.T) {
	s := newCacheOnlySession()
	t0 := time.Unix(1000, 0)
	const held = 20000
	for i := 0; i < held; i++ { // all within the TTL: nothing expires
		s.cacheResponseAt(int64(i), &wire.Response{}, t0.Add(time.Duration(i)*time.Microsecond))
	}
	start := time.Now()
	const more = 2000
	for i := 0; i < more; i++ {
		s.cacheResponseAt(int64(held+i), &wire.Response{}, t0.Add(time.Second).Add(time.Duration(i)*time.Microsecond))
	}
	// Scanning ~20k entries per insert costs ~0.5-1 s for these 2,000; the
	// FIFO does them in about a millisecond.
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("%d inserts into a cache of %d took %v", more, held, d)
	}
	if len(s.respCache) != held+more {
		t.Fatalf("cache holds %d, want %d", len(s.respCache), held+more)
	}
}

// The queue is compacted as it is consumed, so a long-lived session's
// bookkeeping stays proportional to what it holds.
func TestCacheQueueIsCompacted(t *testing.T) {
	s := newCacheOnlySession()
	t0 := time.Unix(1000, 0)
	for i := 0; i < 5000; i++ {
		s.cacheResponseAt(int64(i), &wire.Response{}, t0.Add(time.Duration(i)*time.Minute)) // each expires its predecessor
	}
	if len(s.respCache) != 1 {
		t.Fatalf("cache holds %d, want 1", len(s.respCache))
	}
	if len(s.respOrder) > 2048 {
		t.Fatalf("order queue holds %d records for a cache of 1", len(s.respOrder))
	}
}
