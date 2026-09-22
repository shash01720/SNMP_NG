// Package server implements the NodeTree QUIC server: session management,
// message dispatch (Get/Set/Create/Query/SummaryAck), and error-node
// generation, per node.asn.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/shashi/snmp-ng/goimpl/internal/query"
	"github.com/shashi/snmp-ng/goimpl/internal/reliability"
	"github.com/shashi/snmp-ng/goimpl/internal/tree"
	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

const (
	retransmitInterval = 250 * time.Millisecond
	maxRetransmits     = 8
	ackInterval        = 100 * time.Millisecond
)

type Server struct {
	Tree *tree.Tree

	// MaxDatagramSizeOverride, if set (>0), is used as every session's
	// datagram size budget instead of discovering it from a real
	// quic.DatagramTooLargeError. Mainly for testing/demoing truncation:
	// on a real network path the discovered limit is far larger than this
	// repo's small demo tree would ever exceed.
	MaxDatagramSizeOverride int
}

func New() *Server {
	return &Server{Tree: tree.New()}
}

// Run accepts connections from ln until ctx is done, handling each on its
// own goroutine.
func (s *Server) Run(ctx context.Context, ln *quic.Listener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		sess := s.newSession(conn)
		go sess.run(ctx)
	}
}

// --- Session ----------------------------------------------------------

type Session struct {
	ID     string
	server *Server
	conn   *quic.Conn

	newNodesPath     *tree.Node
	errorsPath       *tree.Node
	queryResultsPath *tree.Node

	sender   *reliability.Sender
	receiver *reliability.Receiver

	seqMu   sync.Mutex
	nextSeq int64

	respCacheMu sync.Mutex
	respCache   map[int64]*wire.Response // keyed by the request's own sequenceNumber

	queriesMu     sync.Mutex
	activeQueries map[int64]*query.Runner

	// maxDatagramMu/maxDatagramSize: this connection's discovered (or
	// overridden) per-datagram payload budget. 0 means "not yet learned";
	// sendFittedNodes/sendBatched discover it lazily from the first
	// quic.DatagramTooLargeError, and cache it here so later sends in the
	// same session don't have to rediscover it.
	maxDatagramMu   sync.Mutex
	maxDatagramSize int
}

func (sess *Session) getMaxDatagramSize() int {
	sess.maxDatagramMu.Lock()
	defer sess.maxDatagramMu.Unlock()
	return sess.maxDatagramSize
}

func (sess *Session) setMaxDatagramSize(n int) {
	sess.maxDatagramMu.Lock()
	defer sess.maxDatagramMu.Unlock()
	sess.maxDatagramSize = n
}

func (s *Server) newSession(conn *quic.Conn) *Session {
	id := randomSessionID()
	sess := &Session{
		ID:            id,
		server:        s,
		conn:          conn,
		respCache:     make(map[int64]*wire.Response),
		activeQueries: make(map[int64]*query.Runner),
	}
	base := s.Tree.EnsurePath("Sessions", "Connection-ID="+id)
	sess.newNodesPath = s.Tree.EnsurePath0(base, "NewNodes")
	sess.errorsPath = s.Tree.EnsurePath0(base, "Errors")
	sess.queryResultsPath = s.Tree.EnsurePath0(base, "QueryResults")

	sess.sender = reliability.NewSender(func(payload []byte) error {
		return conn.SendDatagram(payload)
	}, retransmitInterval, maxRetransmits, func(seq int64) {
		log.Printf("[server] session %s: giving up on unacked datagram (seq %d) after %d attempts", id, seq, maxRetransmits)
	})
	sess.receiver = reliability.NewReceiver()
	if s.MaxDatagramSizeOverride > 0 {
		sess.maxDatagramSize = s.MaxDatagramSizeOverride
	}
	return sess
}

func randomSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (sess *Session) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Printf("[server] session %s: connected (%s)", sess.ID, sess.conn.RemoteAddr())
	defer log.Printf("[server] session %s: closed", sess.ID)

	go sess.sender.RunRetransmitLoop(ctx)
	go sess.ackLoop(ctx)

	defer func() {
		sess.queriesMu.Lock()
		for _, r := range sess.activeQueries {
			r.Stop()
		}
		sess.queriesMu.Unlock()
	}()

	for {
		data, err := sess.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		msg, err := wire.UnmarshalMessage(data)
		if err != nil {
			log.Printf("[server] session %s: malformed datagram: %v", sess.ID, err)
			continue
		}
		sess.handleMessage(ctx, msg)
	}
}

func (sess *Session) ackLoop(ctx context.Context) {
	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ack := sess.receiver.BuildAck()
			if len(ack.Received) == 0 {
				continue
			}
			payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgSummaryAck, SummaryAck: ack})
			_ = sess.conn.SendDatagram(payload) // SummaryAck itself is not reliability-tracked
		}
	}
}

func (sess *Session) allocSeq() int64 {
	sess.seqMu.Lock()
	defer sess.seqMu.Unlock()
	sess.nextSeq++
	return sess.nextSeq
}

// requestSeq extracts the sequenceNumber of a request-carrying message
// (Get/Set/Create/Query); ok is false for Response/SummaryAck, which don't
// participate in this dedup scheme the same way (Response is the *answer*
// to a request seq, not itself deduplicated by it; SummaryAck isn't
// sequence-numbered at all).
func requestSeq(msg wire.Message) (seq int64, ok bool) {
	switch msg.Kind {
	case wire.MsgGet:
		return msg.Get.SequenceNumber, true
	case wire.MsgSet:
		return msg.Set.SequenceNumber, true
	case wire.MsgCreate:
		return msg.Create.SequenceNumber, true
	case wire.MsgQuery:
		return msg.Query.SequenceNumber, true
	default:
		return 0, false
	}
}

func (sess *Session) handleMessage(ctx context.Context, msg wire.Message) {
	if seq, ok := requestSeq(msg); ok {
		isNew := sess.receiver.MarkReceived(seq)
		if !isNew {
			// A retransmit of a request we've already processed (our ack
			// or our response was lost). Resend the cached response
			// rather than reprocessing -- Create in particular is not
			// naturally idempotent, and re-running it would create a
			// second node.
			sess.respCacheMu.Lock()
			cached, have := sess.respCache[seq]
			sess.respCacheMu.Unlock()
			if have {
				sess.sendResponse(cached)
			}
			return
		}
	}

	switch msg.Kind {
	case wire.MsgGet:
		sess.handleGet(msg.Get)
	case wire.MsgSet:
		sess.handleSet(msg.Set)
	case wire.MsgCreate:
		sess.handleCreate(msg.Create)
	case wire.MsgQuery:
		sess.handleQuery(ctx, msg.Query)
	case wire.MsgSummaryAck:
		sess.sender.HandleAck(msg.SummaryAck)
	}
}

// sendResponse sends resp over the reliability layer (a fresh transport
// sequence number each time, even for a resend -- that's independent of
// resp.InReplyTo, which is what the client actually correlates on).
func (sess *Session) sendResponse(resp *wire.Response) {
	txSeq := sess.allocSeq()
	resp.SequenceNumber = txSeq
	payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: resp})
	if err := sess.sender.Send(txSeq, payload); err != nil {
		log.Printf("[server] session %s: send error: %v", sess.ID, err)
	}
}

// respondAndCache sends resp and caches it under requestSeq, for dedup
// (see handleMessage).
func (sess *Session) respondAndCache(requestSeq int64, resp *wire.Response) {
	sess.sendResponse(resp)
	sess.respCacheMu.Lock()
	sess.respCache[requestSeq] = resp
	sess.respCacheMu.Unlock()
}

// sendFittedNodes sends flat[resumeIndex:] as a Response to requestSeq,
// fitting it into one QUIC datagram. If the full remainder doesn't fit, it
// is truncated via tree.FitToSize (rewriting the offset pointer(s) that
// would have reached past the cut into an absolute
// "<baseExpression>@<index>" continuation pointer the client can Get to
// resume) -- see node.asn's NodePointer docs and the repo's Python/UDP
// reference implementation, which this mirrors.
//
// The datagram size budget is learned reactively: quic-go has no proactive
// "max datagram size" query, only a quic.DatagramTooLargeError returned
// from a failed send naming the actual limit (Conn.SendDatagram's doc
// comment). The optimistic first attempt sends the untruncated remainder
// directly; on DatagramTooLargeError, the discovered limit is cached on
// the session (so later sends in the same session skip straight to
// fitting) and a corrected, fitted payload is sent instead.
func (sess *Session) sendFittedNodes(requestSeq int64, flat []wire.Node, resumeIndex int, baseExpression string) {
	txSeq := sess.allocSeq()
	build := func(nodes []wire.Node) *wire.Response {
		return &wire.Response{SequenceNumber: txSeq, InReplyTo: requestSeq, Nodes: nodes}
	}
	measure := func(nodes []wire.Node) int {
		return len(wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: build(nodes)}))
	}

	nodes := flat[resumeIndex:]
	if cached := sess.getMaxDatagramSize(); cached > 0 && measure(nodes) > cached {
		fitted, _ := tree.FitToSize(flat, resumeIndex, baseExpression, cached, measure)
		nodes = fitted
	}

	for attempt := 0; attempt < 2; attempt++ {
		resp := build(nodes)
		payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: resp})

		err := sess.sender.Send(txSeq, payload)
		if err == nil {
			sess.respCacheMu.Lock()
			sess.respCache[requestSeq] = resp
			sess.respCacheMu.Unlock()
			return
		}

		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			log.Printf("[server] session %s: send error: %v", sess.ID, err)
			return
		}
		sess.sender.Cancel(txSeq) // don't blindly retransmit the oversized payload
		sess.setMaxDatagramSize(int(tooLarge.MaxDatagramPayloadSize))

		fitted, _ := tree.FitToSize(flat, resumeIndex, baseExpression, int(tooLarge.MaxDatagramPayloadSize), measure)
		if len(fitted) == 0 && len(nodes) > 0 {
			log.Printf("[server] session %s: cannot fit even one node within max datagram size %d for request seq %d",
				sess.ID, tooLarge.MaxDatagramPayloadSize, requestSeq)
			return
		}
		nodes = fitted
		// loop once more to send the now-fitted payload
	}
	log.Printf("[server] session %s: gave up fitting a response for request seq %d after repeated DatagramTooLargeError",
		sess.ID, requestSeq)
}

// --- error nodes --------------------------------------------------------

// errorCodes used by this server; kept simple (no "/", "=", regex
// metacharacters) so they never need expression escaping.
const (
	errInvalidExpression = "InvalidExpression"
	errNoSuchNode        = "NoSuchNode"
	errAmbiguousTarget   = "AmbiguousTarget"
	errInvalidSet        = "InvalidSet"
	errInvalidQuery      = "InvalidQuery"
	errInternal          = "InternalError"
)

// recordError creates an ErrorNode under this session's own Errors
// subtree and returns an absolute NodePointer to it. Because error nodes
// accumulate (repeated occurrences of the same code become repeated
// siblings, per this protocol's usual array-of-siblings convention), a
// pointer built from just the code matches every occurrence of that code
// for this session, not only the newest one -- acceptable for a reference
// implementation, but worth knowing if you go looking for "the" error.
func (sess *Session) recordError(code, message string, causeSeq int64) wire.NodePointer {
	errNode := sess.server.Tree.AppendUnder(sess.errorsPath, code, wire.NoValue())
	sess.server.Tree.AppendUnder(errNode, "message", wire.StringValue(message))
	sess.server.Tree.AppendUnder(errNode, "requestSequenceNumber", wire.Counter64Value(uint64(causeSeq)))
	path := fmt.Sprintf("/Sessions/Connection-ID\\=%s/Errors/%s", sess.ID, code)
	return wire.AbsolutePointer(path)
}

func (sess *Session) respondError(requestSeq int64, code, message string) {
	errPtr := sess.recordError(code, message, requestSeq)
	log.Printf("[server] session %s: error (%s) for request seq %d: %s", sess.ID, code, requestSeq, message)
	sess.respondAndCache(requestSeq, &wire.Response{
		InReplyTo: requestSeq,
		Error:     true,
		ErrorNode: &errPtr,
	})
}

// --- Get -----------------------------------------------------------------

func (sess *Session) handleGet(g *wire.Get) {
	if g.Target.Kind != wire.PointerAbsolute {
		sess.respondError(g.SequenceNumber, errInvalidExpression, "Get.target must be an absolute expression")
		return
	}
	flat, resumeIndex, base, err := sess.server.Tree.GetFull(g.Target.Absolute)
	if err != nil {
		sess.respondError(g.SequenceNumber, errInvalidExpression, err.Error())
		return
	}
	sess.sendFittedNodes(g.SequenceNumber, flat, resumeIndex, base)
}

// --- Set -------------------------------------------------------------------

func (sess *Session) handleSet(s *wire.Set) {
	if err := sess.server.Tree.Set(s); err != nil {
		code := errInvalidSet
		if s.Target.Kind == wire.PointerAbsolute {
			// A best-effort guess at whether this was "no/ambiguous
			// match" vs. a relink-specific failure, for a slightly more
			// useful error code; either way the message has the details.
			code = errNoSuchNode
		}
		sess.respondError(s.SequenceNumber, code, err.Error())
		return
	}
	sess.respondAndCache(s.SequenceNumber, &wire.Response{InReplyTo: s.SequenceNumber})
}

// --- Create ----------------------------------------------------------------

func (sess *Session) handleCreate(c *wire.Create) {
	value := wire.NoValue()
	if c.Value != nil {
		value = *c.Value
	}
	n := sess.server.Tree.AppendUnder(sess.newNodesPath, c.Key, value)
	sess.respondAndCache(c.SequenceNumber, &wire.Response{
		InReplyTo: c.SequenceNumber,
		Nodes: []wire.Node{{
			Key:         n.Key,
			Value:       n.Value,
			FirstChild:  wire.OffsetPointer(0),
			NextSibling: wire.OffsetPointer(0),
		}},
	})
}

// --- Query -----------------------------------------------------------------

func (sess *Session) handleQuery(ctx context.Context, q *wire.Query) {
	if err := query.ValidateQuery(q); err != nil {
		sess.respondError(q.SequenceNumber, errInvalidQuery, err.Error())
		return
	}
	runner := query.NewRunner(*q, treeSampler{sess.server.Tree}, sessionResultSink{sess})

	sess.queriesMu.Lock()
	sess.activeQueries[q.SequenceNumber] = runner
	sess.queriesMu.Unlock()

	runner.Start(ctx)
	// Acknowledge registration immediately, distinct from the (possibly
	// later, possibly repeated) result pushes that share the same
	// InReplyTo -- the client tells them apart by content (this one always
	// has empty Nodes).
	sess.respondAndCache(q.SequenceNumber, &wire.Response{InReplyTo: q.SequenceNumber})
}

type treeSampler struct{ tree *tree.Tree }

func (s treeSampler) Sample(expression string) ([]query.Sample, error) {
	nodes, err := s.tree.FindAll(expression)
	if err != nil {
		return nil, err
	}
	samples := make([]query.Sample, len(nodes))
	for i, n := range nodes {
		samples[i] = query.Sample{Key: n.Key, Value: n.Value}
	}
	return samples, nil
}

type sessionResultSink struct{ sess *Session }

func (s sessionResultSink) DeliverResults(querySeq int64, results map[string][]wire.NodeValue) error {
	var nodes []wire.Node
	for key, values := range results {
		for _, v := range values {
			n := s.sess.server.Tree.AppendUnder(s.sess.queryResultsPath, key, v)
			nodes = append(nodes, wire.Node{
				Key: n.Key, Value: n.Value,
				FirstChild: wire.OffsetPointer(0), NextSibling: wire.OffsetPointer(0),
			})
		}
	}
	return s.sess.sendBatched(querySeq, nodes)
}

// sendBatched sends `nodes` as one or more Response messages (each with
// its own fresh sequenceNumber, all sharing inReplyTo), splitting across
// multiple datagrams if they don't all fit in one. Unlike sendFittedNodes
// (used for Get, where a node's offset pointers encode real relationships
// to other nodes that must be preserved via a continuation pointer),
// Query's pushed nodes are independent results with no internal pointer
// relationships to preserve (see DeliverResults, above, which always
// gives each one a trivial "none" firstChild/nextSibling), so this only
// needs to split the list into datagram-sized batches -- no offset
// rewriting.
func (sess *Session) sendBatched(inReplyTo int64, nodes []wire.Node) error {
	if len(nodes) == 0 {
		return nil // nothing to push this transfer
	}
	for len(nodes) > 0 {
		txSeq := sess.allocSeq()
		build := func(n []wire.Node) *wire.Response {
			return &wire.Response{SequenceNumber: txSeq, InReplyTo: inReplyTo, Nodes: n}
		}
		measure := func(n []wire.Node) int {
			return len(wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: build(n)}))
		}

		batch := nodes
		if cached := sess.getMaxDatagramSize(); cached > 0 && measure(batch) > cached {
			batch = fitBatch(nodes, cached, measure)
		}

		sent := false
		for attempt := 0; attempt < 2; attempt++ {
			payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: build(batch)})
			err := sess.sender.Send(txSeq, payload)
			if err == nil {
				sent = true
				break
			}
			var tooLarge *quic.DatagramTooLargeError
			if !errors.As(err, &tooLarge) {
				return err
			}
			sess.sender.Cancel(txSeq)
			sess.setMaxDatagramSize(int(tooLarge.MaxDatagramPayloadSize))
			batch = fitBatch(nodes, int(tooLarge.MaxDatagramPayloadSize), measure)
			if len(batch) == 0 {
				return fmt.Errorf("cannot fit even one node within max datagram size %d", tooLarge.MaxDatagramPayloadSize)
			}
		}
		if !sent {
			return fmt.Errorf("gave up fitting a batch after repeated DatagramTooLargeError")
		}
		nodes = nodes[len(batch):]
	}
	return nil
}

// fitBatch returns the largest prefix of nodes whose batch fits within
// maxSize, per measure.
func fitBatch(nodes []wire.Node, maxSize int, measure func([]wire.Node) int) []wire.Node {
	for n := len(nodes); n > 0; n-- {
		if measure(nodes[:n]) <= maxSize {
			return nodes[:n]
		}
	}
	return nil
}
