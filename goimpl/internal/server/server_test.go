package server

import (
	"context"
	"crypto/tls"
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
			baseline = values(r)
		}
	}
	if strings.Join(baseline, ",") != "timeout=30" {
		t.Fatalf("baseline push: %v", baseline)
	}

	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	if got := values(mustOK(t, c.next(qseq))); strings.Join(got, ",") != "timeout=99" {
		t.Fatalf("change push: %v", got)
	}

	// Setting the same value again is not a change.
	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(99)))
	c.expectNone(qseq, 1500*time.Millisecond)

	mustOK(t, c.del(c.sessionPath()+"/QueryResults/Query-SequenceNumber.*"))
	mustOK(t, c.setValue("/config/timeout", wire.Integer32Value(7)))
	c.expectNone(qseq, 1500*time.Millisecond)
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
