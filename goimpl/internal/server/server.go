// Package server implements the NodeTree QUIC server: session management,
// message dispatch (Get/Set/Create/Query/SummaryAck), and error-node
// generation, per node.asn.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	nodes, err := sess.server.Tree.Get(g.Target.Absolute)
	if err != nil {
		sess.respondError(g.SequenceNumber, errInvalidExpression, err.Error())
		return
	}
	sess.respondAndCache(g.SequenceNumber, &wire.Response{InReplyTo: g.SequenceNumber, Nodes: nodes})
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
	txSeq := s.sess.allocSeq()
	resp := &wire.Response{SequenceNumber: txSeq, InReplyTo: querySeq, Nodes: nodes}
	payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: resp})
	return s.sess.sender.Send(txSeq, payload)
}
