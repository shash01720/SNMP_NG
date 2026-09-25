// Command client is a CLI for the NodeTree QUIC server: get / set / create /
// query.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/shashi/snmp-ng/goimpl/internal/certs"
	"github.com/shashi/snmp-ng/goimpl/internal/reliability"
	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

const (
	retransmitInterval = 250 * time.Millisecond
	maxRetransmits     = 8
	ackInterval        = 100 * time.Millisecond
	requestTimeout     = 5 * time.Second

	// maxIdleTimeout/keepAlivePeriod: see cmd/server/main.go's doc comment
	// on the same constants -- both sides need this set, not just one, so
	// a long `query --on-change --watch` sitting quietly survives quic-go's
	// own idle timeout regardless of which direction happens to go quiet
	// first.
	maxIdleTimeout  = 30 * time.Second
	keepAlivePeriod = 10 * time.Second
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8515", "server address")
	caFile := flag.String("ca", "", "CA certificate (PEM) to verify the server against; omit to skip verification (demo only)")
	certFile := flag.String("cert", "", "client certificate (PEM) to present; its CommonName is this client's identity")
	keyFile := flag.String("key", "", "client private key (PEM)")
	serverName := flag.String("server-name", "", "name expected in the server certificate (default: the host part of -addr)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-addr host:port] <command> [args...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "commands:\n")
		fmt.Fprintf(os.Stderr, "  get <expression>\n")
		fmt.Fprintf(os.Stderr, "  set [--value V] [--first-child EXPR|none] [--next-sibling EXPR|none] [--new-parent EXPR] <expression> [expression...]\n")
		fmt.Fprintf(os.Stderr, "  delete <expression> [expression...]\n")
		fmt.Fprintf(os.Stderr, "  create [--parent EXPR] <key> [value]\n")
		fmt.Fprintf(os.Stderr, "  query <expression> [--collection SECONDS | --on-change] --transfer SECONDS [--agg-interval SECONDS --agg-method min|max|mean|stddev|pNN]\n")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	// No overall timeout here: a hardcoded one previously capped every
	// invocation's total lifetime, which silently killed any `query
	// --on-change --watch` (or plain --watch) longer than that cap,
	// independent of whether the QUIC connection itself would have
	// survived. Bounding is left to what actually needs it -- each
	// request's own requestTimeout, and query's own --watch duration.
	ctx := context.Background()

	tlsConf := certs.ClientConfig()
	if *caFile != "" {
		name := *serverName
		if name == "" {
			name, _, _ = net.SplitHostPort(*addr)
		}
		var terr error
		if tlsConf, terr = certs.ClientTLSConfig(*certFile, *keyFile, *caFile, name); terr != nil {
			log.Fatalf("loading TLS config: %v", terr)
		}
	} else if *certFile != "" {
		log.Fatalf("-cert needs -ca: presenting a certificate to a server that isn't verified would be pointless")
	}

	conn, err := quic.DialAddr(ctx, *addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  maxIdleTimeout,
		KeepAlivePeriod: keepAlivePeriod,
	})
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	c := newClient(conn)
	go c.readLoop(ctx)
	go c.sender.RunRetransmitLoop(ctx)
	go c.ackLoop(ctx)

	switch args[0] {
	case "get":
		runGet(ctx, c, args[1:])
	case "set":
		runSet(ctx, c, args[1:])
	case "delete":
		runDelete(ctx, c, args[1:])
	case "create":
		runCreate(ctx, c, args[1:])
	case "query":
		runQuery(ctx, c, args[1:])
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// --- client plumbing ---------------------------------------------------

type client struct {
	conn     *quic.Conn
	sender   *reliability.Sender
	receiver *reliability.Receiver

	seqMu   sync.Mutex
	nextSeq int64

	respMu    sync.Mutex
	respChans map[int64]chan *wire.Response

	pushMu      sync.Mutex
	pushHandler func(*wire.Response)
}

func newClient(conn *quic.Conn) *client {
	c := &client{conn: conn, respChans: make(map[int64]chan *wire.Response)}
	c.sender = reliability.NewSender(func(p []byte) error {
		return conn.SendDatagram(p)
	}, retransmitInterval, maxRetransmits, func(seq int64) {
		log.Printf("[client] giving up on unacked datagram (seq %d)", seq)
	})
	c.receiver = reliability.NewReceiver()
	return c
}

func (c *client) allocSeq() int64 {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	c.nextSeq++
	return c.nextSeq
}

func (c *client) readLoop(ctx context.Context) {
	for {
		data, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		msg, err := wire.UnmarshalMessage(data)
		if err != nil {
			log.Printf("[client] malformed datagram: %v", err)
			continue
		}
		switch msg.Kind {
		case wire.MsgResponse:
			r := msg.Response
			if c.receiver.MarkReceived(r.SequenceNumber) {
				c.dispatchResponse(r)
			}
		case wire.MsgSummaryAck:
			c.sender.HandleAck(msg.SummaryAck)
		}
	}
}

func (c *client) dispatchResponse(r *wire.Response) {
	c.respMu.Lock()
	ch, ok := c.respChans[r.InReplyTo]
	c.respMu.Unlock()
	if ok {
		select {
		case ch <- r:
		default:
		}
		return
	}
	c.pushMu.Lock()
	h := c.pushHandler
	c.pushMu.Unlock()
	if h != nil {
		h(r)
	}
}

func (c *client) ackLoop(ctx context.Context) {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ack := c.receiver.BuildAck()
			if len(ack.Received) == 0 {
				continue
			}
			_ = c.conn.SendDatagram(wire.MarshalMessage(wire.Message{Kind: wire.MsgSummaryAck, SummaryAck: ack}))
		}
	}
}

// sendAndWait sends msg (whose Kind determines its embedded
// sequenceNumber) and blocks for the first Response with a matching
// InReplyTo.
func (c *client) sendAndWait(ctx context.Context, seq int64, msg wire.Message) (*wire.Response, error) {
	ch := make(chan *wire.Response, 1)
	c.respMu.Lock()
	c.respChans[seq] = ch
	c.respMu.Unlock()
	defer func() {
		c.respMu.Lock()
		delete(c.respChans, seq)
		c.respMu.Unlock()
	}()

	if err := c.sender.Send(seq, wire.MarshalMessage(msg)); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-time.After(requestTimeout):
		return nil, fmt.Errorf("timeout waiting for response (seq %d)", seq)
	case <-c.conn.Context().Done():
		// e.g. the server rejected our certificate: under TLS 1.3 the
		// handshake finishes on the client before the server validates the
		// client's certificate, so the rejection only shows up as the
		// connection being closed -- surface that instead of a bare timeout.
		return nil, fmt.Errorf("connection closed: %w", context.Cause(c.conn.Context()))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// --- printing ------------------------------------------------------------

func printResponse(label string, r *wire.Response) {
	if r.Error {
		errRef := "?"
		if r.ErrorNode != nil {
			errRef = r.ErrorNode.Absolute
		}
		fmt.Printf("%s: ERROR (see %s)\n", label, errRef)
		return
	}
	fmt.Printf("%s: %d node(s)\n", label, len(r.Nodes))
	for _, n := range r.Nodes {
		fmt.Printf("    key=%q value=%s firstChild=%s nextSibling=%s\n",
			n.Key, formatValue(n.Value), formatPointer(n.FirstChild), formatPointer(n.NextSibling))
	}
}

func formatPointer(p wire.NodePointer) string {
	switch p.Kind {
	case wire.PointerOffset:
		if p.Offset == 0 {
			return "none"
		}
		return fmt.Sprintf("+%d", p.Offset)
	case wire.PointerAbsolute:
		return fmt.Sprintf("-> %q", p.Absolute) // a continuation pointer, if the result was truncated
	default:
		return "none"
	}
}

func formatValue(v wire.NodeValue) string {
	switch v.Kind {
	case wire.ValueInteger32:
		return fmt.Sprintf("int32(%d)", v.Integer32)
	case wire.ValueUnsigned32:
		return fmt.Sprintf("uint32(%d)", v.Unsigned32)
	case wire.ValueCounter32:
		return fmt.Sprintf("counter32(%d)", v.Counter32)
	case wire.ValueCounter64:
		return fmt.Sprintf("counter64(%d)", v.Counter64)
	case wire.ValueTimeTicks:
		return fmt.Sprintf("timeTicks(%d)", v.TimeTicks)
	case wire.ValueOctetString:
		return fmt.Sprintf("%q", string(v.OctetString))
	case wire.ValueReal:
		return fmt.Sprintf("real(%g)", v.Real)
	case wire.ValueNoValue:
		return "(none)"
	default:
		return "(unknown)"
	}
}

// --- commands --------------------------------------------------------------

// maxFollowups guards against a cyclic or misbehaving server sending
// continuation pointers forever.
const maxFollowups = 50

func runGet(ctx context.Context, c *client, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: get <expression>")
		os.Exit(2)
	}
	followGet(ctx, c, "get", args[0])
}

// followGet sends expression as a Get, prints the Response, and then
// automatically issues a fresh Get for every absolute NodePointer found in
// a returned node's firstChild/nextSibling: a continuation the server
// generated because the full result didn't fit in one QUIC datagram (see
// node.asn's NodePointer docs and internal/tree.FitToSize) -- repeating
// until no continuations remain, so the caller always sees the complete,
// correctly-linked result regardless of how many datagrams it took.
func followGet(ctx context.Context, c *client, label, expression string) {
	q := newContinuationQueue()
	q.Add(expression)
	followups := 0

	for {
		expr, ok := q.Next()
		if !ok {
			break
		}

		seq := c.allocSeq()
		msg := wire.Message{Kind: wire.MsgGet, Get: &wire.Get{SequenceNumber: seq, Target: wire.AbsolutePointer(expr)}}
		resp, err := c.sendAndWait(ctx, seq, msg)
		if err != nil {
			log.Fatalf("get: %v", err)
		}
		q.MarkCovered(expr, len(resp.Nodes))

		batchLabel := label
		if expr != expression {
			batchLabel = fmt.Sprintf("%s (continuation of %q)", label, expr)
		}
		printResponse(batchLabel, resp)

		for _, n := range resp.Nodes {
			for _, p := range []wire.NodePointer{n.FirstChild, n.NextSibling} {
				if p.Kind != wire.PointerAbsolute {
					continue
				}
				if followups >= maxFollowups {
					log.Printf("get: hit max-followups=%d, not following %q", maxFollowups, p.Absolute)
					continue
				}
				if q.Add(p.Absolute) {
					followups++
				}
			}
		}
	}
}

// runSet applies the same --value/--first-child/--next-sibling edit to
// every expression given, as one atomic multi-edit Set request (see
// node.asn's SetEdit docs). --value matches wire.Set's own regex-based,
// zero-or-more-node semantics: it's applied to every node each expression
// matches, not just a single one. --first-child/--next-sibling remain
// structural, single-node operations -- each expression used with either
// must resolve to exactly one node, or the whole Set is rejected.
func runSet(ctx context.Context, c *client, args []string) {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	value := fs.String("value", "", "new string value, applied to every node each expression matches")
	firstChild := fs.String("first-child", "", "new firstChild: an expression, or 'none' (each expression must match exactly 1 node)")
	nextSibling := fs.String("next-sibling", "", "new nextSibling: an expression, or 'none' (each expression must match exactly 1 node)")
	newParent := fs.String("new-parent", "", "reparent each expression's (staged) node to become the last child of this expression's node -- commits a subtree staged via 'create' into live config")
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: set [--value V] [--first-child EXPR|none] [--next-sibling EXPR|none] [--new-parent EXPR] <expression> [expression...]")
		os.Exit(2)
	}

	s := &wire.Set{}
	for _, expr := range fs.Args() {
		edit := wire.SetEdit{Target: expr}
		if *value != "" {
			v := wire.StringValue(*value)
			edit.NewValue = &v
		}
		if *firstChild != "" {
			edit.NewFirstChild = parsePointerFlag(*firstChild)
		}
		if *nextSibling != "" {
			edit.NewNextSibling = parsePointerFlag(*nextSibling)
		}
		if *newParent != "" {
			edit.NewParent = newParent
		}
		s.Edits = append(s.Edits, edit)
	}

	seq := c.allocSeq()
	s.SequenceNumber = seq
	resp, err := c.sendAndWait(ctx, seq, wire.Message{Kind: wire.MsgSet, Set: s})
	if err != nil {
		log.Fatalf("set: %v", err)
	}
	printResponse("set", resp)
}

// runDelete deletes every node matched by any expression given, in one
// Delete request -- the server computes whatever parent/sibling relink is
// needed itself (see node.asn's Delete docs).
func runDelete(ctx context.Context, c *client, args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: delete <expression> [expression...]")
		os.Exit(2)
	}

	d := &wire.Delete{Targets: fs.Args()}
	seq := c.allocSeq()
	d.SequenceNumber = seq
	resp, err := c.sendAndWait(ctx, seq, wire.Message{Kind: wire.MsgDelete, Delete: d})
	if err != nil {
		log.Fatalf("delete: %v", err)
	}
	printResponse("delete", resp)
}

func parsePointerFlag(s string) *wire.NodePointer {
	if s == "none" {
		p := wire.NonePointer()
		return &p
	}
	p := wire.AbsolutePointer(s)
	return &p
}

// runCreate creates one node. By default it's appended directly under this
// session's own staged NewNodes; --parent, if given, must be an expression
// resolving to NewNodes itself or one of its own descendants (an earlier
// Create's own result, letting a subtree be built up staged-node by
// staged-node -- see node.asn's Create docs) rather than anywhere in live
// config.
func runCreate(ctx context.Context, c *client, args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	parent := fs.String("parent", "", "an expression naming an existing staged node (this session's own NewNodes, or one of its descendants) to create under instead of NewNodes itself")
	fs.Parse(args)
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(os.Stderr, "usage: create [--parent EXPR] <key> [value]")
		os.Exit(2)
	}
	seq := c.allocSeq()
	create := &wire.Create{SequenceNumber: seq, Key: fs.Arg(0)}
	if fs.NArg() == 2 {
		v := wire.StringValue(fs.Arg(1))
		create.Value = &v
	}
	if *parent != "" {
		create.Parent = parent
	}
	resp, err := c.sendAndWait(ctx, seq, wire.Message{Kind: wire.MsgCreate, Create: create})
	if err != nil {
		log.Fatalf("create: %v", err)
	}
	printResponse("create", resp)
}

func runQuery(ctx context.Context, c *client, args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	collection := fs.Int64("collection", 0, "collection interval in seconds (0 = ONCE); ignored if --on-change")
	onChange := fs.Bool("on-change", false, "collect only when a matched value actually changes, event-triggered instead of on a timer")
	transfer := fs.Int64("transfer", 0, "transfer interval in seconds")
	aggInterval := fs.Int64("agg-interval", 0, "aggregation interval in seconds (0 = no aggregation)")
	aggMethod := fs.String("agg-method", "", "min|max|mean|stddev|pNN (e.g. p95)")
	watch := fs.Duration("watch", 10*time.Second, "how long to keep printing pushed results before exiting")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: query <expression> [--collection SECONDS | --on-change] --transfer SECONDS [--agg-interval SECONDS --agg-method min|max|mean|stddev|pNN] [--watch DURATION]")
		os.Exit(2)
	}

	mode := wire.IntervalMode(*collection)
	if *collection == 0 {
		mode = wire.OnceMode()
	}
	if *onChange {
		mode = wire.OnChangeMode()
	}

	q := &wire.Query{
		NodeExpression:   fs.Arg(0),
		CollectionMode:   mode,
		TransferInterval: *transfer,
	}
	if *aggInterval > 0 {
		q.AggregationInterval = aggInterval
		method, err := parseAggMethod(*aggMethod)
		if err != nil {
			log.Fatalf("query: %v", err)
		}
		q.AggregationMethod = method
	}

	seq := c.allocSeq()
	q.SequenceNumber = seq

	var pushWg sync.WaitGroup
	pushWg.Add(1)
	done := make(chan struct{})
	c.pushMu.Lock()
	c.pushHandler = func(r *wire.Response) {
		if r.InReplyTo != seq {
			return
		}
		printResponse(fmt.Sprintf("query push (seq %d)", r.SequenceNumber), r)
	}
	c.pushMu.Unlock()
	go func() {
		defer pushWg.Done()
		select {
		case <-time.After(*watch):
		case <-done:
		}
	}()

	resp, err := c.sendAndWait(ctx, seq, wire.Message{Kind: wire.MsgQuery, Query: q})
	if err != nil {
		log.Fatalf("query: %v", err)
	}
	// For a recurring (interval or onChange) query this is always the
	// empty registration ack (results arrive later via pushHandler). For a
	// ONCE query, the server runs the whole collect/aggregate/transfer
	// pipeline synchronously before sending that ack, so the first
	// response received here is often the actual result instead -- label
	// by content, not by assumed arrival order.
	if len(resp.Nodes) == 0 {
		printResponse("query registered", resp)
	} else {
		printResponse(fmt.Sprintf("query push (seq %d)", resp.SequenceNumber), resp)
	}

	if mode.Kind == wire.CollectOnce {
		// ONCE: the server already ran the whole pipeline synchronously
		// and its one push may already be in flight; give it a moment.
		time.Sleep(500 * time.Millisecond)
		close(done)
	}
	pushWg.Wait()
}

func parseAggMethod(s string) (*wire.AggregationMethod, error) {
	switch s {
	case "min":
		return &wire.AggregationMethod{Kind: wire.AggMin}, nil
	case "max":
		return &wire.AggregationMethod{Kind: wire.AggMax}, nil
	case "mean":
		return &wire.AggregationMethod{Kind: wire.AggMean}, nil
	case "stddev":
		return &wire.AggregationMethod{Kind: wire.AggStdDev}, nil
	default:
		if len(s) > 1 && s[0] == 'p' {
			n, err := strconv.Atoi(s[1:])
			if err == nil && n >= 0 && n <= 100 {
				return &wire.AggregationMethod{Kind: wire.AggPercentile, Percentile: int64(n)}, nil
			}
		}
		return nil, fmt.Errorf("bad --agg-method %q (want min|max|mean|stddev|pNN)", s)
	}
}
