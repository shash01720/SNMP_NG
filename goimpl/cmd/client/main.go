// Command client is a CLI for the NodeTree QUIC server: get / set / create /
// query.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8515", "server address")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-addr host:port] <command> [args...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "commands:\n")
		fmt.Fprintf(os.Stderr, "  get <expression>\n")
		fmt.Fprintf(os.Stderr, "  set <expression> [--value V] [--first-child EXPR|none] [--next-sibling EXPR|none]\n")
		fmt.Fprintf(os.Stderr, "  create <key> [value]\n")
		fmt.Fprintf(os.Stderr, "  query <expression> --collection SECONDS --transfer SECONDS [--agg-interval SECONDS --agg-method min|max|mean|stddev|pNN]\n")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, *addr, certs.ClientConfig(), &quic.Config{EnableDatagrams: true})
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

func runSet(ctx context.Context, c *client, args []string) {
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	value := fs.String("value", "", "new string value")
	firstChild := fs.String("first-child", "", "new firstChild: an expression, or 'none'")
	nextSibling := fs.String("next-sibling", "", "new nextSibling: an expression, or 'none'")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: set <expression> [--value V] [--first-child EXPR|none] [--next-sibling EXPR|none]")
		os.Exit(2)
	}
	target := fs.Arg(0)

	s := &wire.Set{Target: wire.AbsolutePointer(target)}
	if *value != "" {
		v := wire.StringValue(*value)
		s.NewValue = &v
	}
	if *firstChild != "" {
		s.NewFirstChild = parsePointerFlag(*firstChild)
	}
	if *nextSibling != "" {
		s.NewNextSibling = parsePointerFlag(*nextSibling)
	}

	seq := c.allocSeq()
	s.SequenceNumber = seq
	resp, err := c.sendAndWait(ctx, seq, wire.Message{Kind: wire.MsgSet, Set: s})
	if err != nil {
		log.Fatalf("set: %v", err)
	}
	printResponse("set", resp)
}

func parsePointerFlag(s string) *wire.NodePointer {
	if s == "none" {
		p := wire.NonePointer()
		return &p
	}
	p := wire.AbsolutePointer(s)
	return &p
}

func runCreate(ctx context.Context, c *client, args []string) {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: create <key> [value]")
		os.Exit(2)
	}
	seq := c.allocSeq()
	create := &wire.Create{SequenceNumber: seq, Key: args[0]}
	if len(args) == 2 {
		v := wire.StringValue(args[1])
		create.Value = &v
	}
	resp, err := c.sendAndWait(ctx, seq, wire.Message{Kind: wire.MsgCreate, Create: create})
	if err != nil {
		log.Fatalf("create: %v", err)
	}
	printResponse("create", resp)
}

func runQuery(ctx context.Context, c *client, args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	collection := fs.Int64("collection", 0, "collection interval in seconds (0 = ONCE)")
	transfer := fs.Int64("transfer", 0, "transfer interval in seconds")
	aggInterval := fs.Int64("agg-interval", 0, "aggregation interval in seconds (0 = no aggregation)")
	aggMethod := fs.String("agg-method", "", "min|max|mean|stddev|pNN (e.g. p95)")
	watch := fs.Duration("watch", 10*time.Second, "how long to keep printing pushed results before exiting")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: query <expression> --collection SECONDS --transfer SECONDS [--agg-interval SECONDS --agg-method min|max|mean|stddev|pNN] [--watch DURATION]")
		os.Exit(2)
	}

	q := &wire.Query{
		NodeExpression:     fs.Arg(0),
		CollectionInterval: *collection,
		TransferInterval:   *transfer,
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
	// For a recurring query this is always the empty registration ack
	// (results arrive later via pushHandler). For a ONCE query
	// (collectionInterval=0), the server runs the whole collect/aggregate/
	// transfer pipeline synchronously before sending that ack, so the
	// first response received here is often the actual result instead --
	// label by content, not by assumed arrival order.
	if len(resp.Nodes) == 0 {
		printResponse("query registered", resp)
	} else {
		printResponse(fmt.Sprintf("query push (seq %d)", resp.SequenceNumber), resp)
	}

	if *collection == 0 {
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
