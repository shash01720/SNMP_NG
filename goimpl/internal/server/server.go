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
	respCache   map[int64]cachedResponse // keyed by the request's own sequenceNumber

	queriesMu     sync.Mutex
	activeQueries map[int64]*query.Runner
	// queryResultNodes tracks each active query's own results subcontainer
	// (see node.asn's SESSION PATHS docs), so reapCancelledQueries can tell
	// whether a Delete/Set detached it (or an ancestor of it) and, if so,
	// cancel that query -- per-query cancellation without a dedicated
	// message. Guarded by queriesMu alongside activeQueries, which it's
	// always kept in sync with.
	queryResultNodes map[int64]*tree.Node

	// overrideSize is a copy of Server.MaxDatagramSizeOverride, fixed at
	// session creation and never mutated afterward -- safe to read without
	// a lock. When set (>0), getMaxDatagramSize always returns it rather
	// than a discovered value: see setMaxDatagramSize for why.
	overrideSize int

	// maxDatagramMu/maxDatagramSize: this connection's discovered
	// per-datagram payload budget, used only when overrideSize is unset.
	// 0 means "not yet learned"; sendFittedNodes/sendBatched discover it
	// lazily from the first quic.DatagramTooLargeError, and cache it here
	// so later sends in the same session don't have to rediscover it.
	maxDatagramMu   sync.Mutex
	maxDatagramSize int
}

// getMaxDatagramSize returns the size a new top-level send should start
// from: the operator's override if one is configured, else the last
// discovered real limit (0 if none yet).
func (sess *Session) getMaxDatagramSize() int {
	if sess.overrideSize > 0 {
		return sess.overrideSize
	}
	sess.maxDatagramMu.Lock()
	defer sess.maxDatagramMu.Unlock()
	return sess.maxDatagramSize
}

// setMaxDatagramSize records a real DatagramTooLargeError-discovered limit
// for future top-level sends in this session. It is a no-op when an
// override is configured: QUIC's path MTU discovery ramps up over a
// connection's lifetime (RFC 9000), so a single early failure -- often
// just the conservative startup size, not the path's real ceiling --
// shouldn't permanently pin every later send below the size the operator
// explicitly asked for. getMaxDatagramSize keeps returning the override so
// each new request retries at it; the discovered value passed here is
// still used directly by the caller to fit and retry the one send that
// just failed.
func (sess *Session) setMaxDatagramSize(n int) {
	if sess.overrideSize > 0 {
		return
	}
	sess.maxDatagramMu.Lock()
	defer sess.maxDatagramMu.Unlock()
	sess.maxDatagramSize = n
}

func (s *Server) newSession(conn *quic.Conn) *Session {
	id := randomSessionID()
	sess := &Session{
		ID:               id,
		server:           s,
		conn:             conn,
		respCache:        make(map[int64]cachedResponse),
		activeQueries:    make(map[int64]*query.Runner),
		queryResultNodes: make(map[int64]*tree.Node),
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
	sess.overrideSize = s.MaxDatagramSizeOverride
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
	case wire.MsgDelete:
		return msg.Delete.SequenceNumber, true
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
				sess.sendResponse(cached.resp)
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
	case wire.MsgDelete:
		sess.handleDelete(msg.Delete)
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
// respCacheTTL bounds respCache's lifetime, not its size: an entry only
// needs to survive long enough to answer a retransmitted duplicate of the
// request it belongs to, and the client's own sender gives up retrying
// after maxRetransmits * retransmitInterval (2s at current settings). 30s
// is a generous multiple of that -- comfortable margin for scheduling
// jitter -- while still keeping the map's size bounded by recent traffic
// rather than growing for a session's entire (potentially very long)
// lifetime, which respCache did until this was added.
const respCacheTTL = 30 * time.Second

type cachedResponse struct {
	resp *wire.Response
	at   time.Time
}

func (sess *Session) respondAndCache(requestSeq int64, resp *wire.Response) {
	sess.sendResponse(resp)
	sess.cacheResponse(requestSeq, resp)
}

// cacheResponse records resp and sweeps any entry older than respCacheTTL.
// Sweeping on every insert (rather than on a separate ticker) needs no
// extra goroutine and keeps the map small in practice, since it only ever
// holds entries from roughly the last respCacheTTL of traffic.
func (sess *Session) cacheResponse(requestSeq int64, resp *wire.Response) {
	sess.respCacheMu.Lock()
	defer sess.respCacheMu.Unlock()
	now := time.Now()
	sess.respCache[requestSeq] = cachedResponse{resp: resp, at: now}
	for seq, c := range sess.respCache {
		if now.Sub(c.at) > respCacheTTL {
			delete(sess.respCache, seq)
		}
	}
}

// sendFittedNodes sends flat[resumeIndex:] as a Response to requestSeq,
// fitting it into one QUIC datagram. If the full remainder doesn't fit, it
// is truncated via tree.FitToSize (rewriting the offset pointer(s) that
// would have reached past the cut into an absolute
// "<baseExpression>@<index>" continuation pointer the client can Get to
// resume) -- see node.asn's NodePointer docs and the earlier Python/UDP
// prototype this mirrors.
//
// The datagram size budget is learned reactively: quic-go has no proactive
// "max datagram size" query, only a quic.DatagramTooLargeError returned
// from a failed send naming the actual limit (Conn.SendDatagram's doc
// comment). The optimistic first attempt sends the untruncated remainder
// directly; on DatagramTooLargeError, a corrected, fitted payload is sent
// instead. When no --max-datagram-size override is configured, the
// discovered limit is also cached on the session so later sends in the
// same session skip straight to fitting; see setMaxDatagramSize for why
// that caching is skipped when an override is set.
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
			sess.cacheResponse(requestSeq, resp)
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
	errInvalidDelete     = "InvalidDelete"
	errInvalidCreate     = "InvalidCreate"
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
	touched, err := sess.server.Tree.Set(s, sess.newNodesPath)
	if err != nil {
		// Set's edits can each fail for a different reason (bad expression,
		// wrong match count, a relink conflict between two edits), so
		// there's no single more-specific code worth guessing at here the
		// way handleGet's errInvalidExpression can be -- errInvalidSet plus
		// the message (which names the offending target) is what a caller
		// actually needs.
		sess.respondError(s.SequenceNumber, errInvalidSet, err.Error())
		return
	}
	sess.reapCancelledQueries()
	sess.respondAndCache(s.SequenceNumber, &wire.Response{
		InReplyTo: s.SequenceNumber,
		Nodes:     confirmationNodes(touched),
	})
}

// --- Delete ------------------------------------------------------------------

func (sess *Session) handleDelete(d *wire.Delete) {
	deleted, err := sess.server.Tree.Delete(d.Targets)
	if err != nil {
		sess.respondError(d.SequenceNumber, errInvalidDelete, err.Error())
		return
	}
	sess.reapCancelledQueries()
	sess.respondAndCache(d.SequenceNumber, &wire.Response{
		InReplyTo: d.SequenceNumber,
		Nodes:     confirmationNodes(deleted),
	})
}

// --- Create ----------------------------------------------------------------

func (sess *Session) handleCreate(c *wire.Create) {
	value := wire.NoValue()
	if c.Value != nil {
		value = *c.Value
	}
	parentExpr := ""
	if c.Parent != nil {
		parentExpr = *c.Parent
	}
	n, err := sess.server.Tree.CreateStaged(sess.newNodesPath, parentExpr, c.Key, value)
	if err != nil {
		sess.respondError(c.SequenceNumber, errInvalidCreate, err.Error())
		return
	}
	sess.respondAndCache(c.SequenceNumber, &wire.Response{
		InReplyTo: c.SequenceNumber,
		Nodes:     confirmationNodes([]*tree.Node{n}),
	})
}

// confirmationNodes maps tree nodes to a flat wire.Node list reporting
// exactly what Set/Create/Delete touched. These are independent
// confirmation entries, not a real flattened subtree walk (see
// tree.FlattenMatches for that), so firstChild/nextSibling are always the
// "none" sentinel.
func confirmationNodes(nodes []*tree.Node) []wire.Node {
	out := make([]wire.Node, len(nodes))
	for i, n := range nodes {
		out[i] = wire.Node{
			Key:         n.Key,
			Value:       n.Value,
			FirstChild:  wire.OffsetPointer(0),
			NextSibling: wire.OffsetPointer(0),
		}
	}
	return out
}

// --- Query -----------------------------------------------------------------

func (sess *Session) handleQuery(ctx context.Context, q *wire.Query) {
	if err := query.ValidateQuery(q); err != nil {
		sess.respondError(q.SequenceNumber, errInvalidQuery, err.Error())
		return
	}

	// Every query gets its own results subcontainer, created up front
	// (before any push, if any) so a client can address it -- to Get it,
	// or to Delete it and cancel the query -- from the moment registration
	// is acknowledged. See node.asn's SESSION PATHS docs.
	resultsNode := sess.server.Tree.AppendUnder(sess.queryResultsPath,
		fmt.Sprintf("Query-SequenceNumber=%d", q.SequenceNumber), wire.NoValue())

	runner := query.NewRunner(*q, treeSampler{sess.server.Tree}, sessionResultSink{sess: sess, resultsNode: resultsNode})

	sess.queriesMu.Lock()
	sess.activeQueries[q.SequenceNumber] = runner
	sess.queryResultNodes[q.SequenceNumber] = resultsNode
	sess.queriesMu.Unlock()

	runner.Start(ctx)

	if q.CollectionMode.Kind == wire.CollectOnce {
		// Start already ran the whole collect/aggregate/transfer pipeline
		// synchronously and returned -- there's no goroutine left running
		// for this entry to track, so don't let a session that issues many
		// ONCE queries over a long lifetime accumulate a dead entry per
		// query forever. The results node itself stays (a client can still
		// Get or Delete it as ordinary cleanup, just without the "also
		// cancel a runner" side effect, since there's no runner left).
		// Interval/onChange queries stay in both maps: they have a real
		// background goroutine, cancellable either by deleting
		// resultsNode or by session teardown (run()'s deferred loop over
		// activeQueries), whichever comes first.
		sess.queriesMu.Lock()
		delete(sess.activeQueries, q.SequenceNumber)
		delete(sess.queryResultNodes, q.SequenceNumber)
		sess.queriesMu.Unlock()
	}

	// Acknowledge registration immediately, distinct from the (possibly
	// later, possibly repeated) result pushes that share the same
	// InReplyTo -- the client tells them apart by content (this one always
	// has empty Nodes).
	sess.respondAndCache(q.SequenceNumber, &wire.Response{InReplyTo: q.SequenceNumber})
}

// reapCancelledQueries stops (and forgets) every active query whose own
// results node is no longer reachable from the tree root -- e.g. because a
// Delete or Set just detached it, or detached an ancestor of it. Called
// after any operation that could have detached a subtree (handleDelete,
// handleSet); cheap and a no-op when nothing relevant happened, since it
// only touches this session's own queryResultNodes.
func (sess *Session) reapCancelledQueries() {
	sess.queriesMu.Lock()
	defer sess.queriesMu.Unlock()
	for seq, node := range sess.queryResultNodes {
		if sess.server.Tree.IsReachable(node) {
			continue
		}
		if r, ok := sess.activeQueries[seq]; ok {
			r.Stop()
			delete(sess.activeQueries, seq)
		}
		delete(sess.queryResultNodes, seq)
	}
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

// ChangedSince implements query.ChangeWaiter, letting a CollectOnChange
// Runner block on the live tree's own mutations instead of polling.
func (s treeSampler) ChangedSince(since uint64) (<-chan struct{}, uint64) {
	return s.tree.ChangedSince(since)
}

// sessionResultSink delivers one query's results under its own
// resultsNode (see handleQuery), not the session's shared QueryResults
// directly -- that per-query scoping is what lets Delete target one
// query's results (and thereby cancel it) without disturbing any other
// active query in the same session.
type sessionResultSink struct {
	sess        *Session
	resultsNode *tree.Node
}

func (s sessionResultSink) DeliverResults(querySeq int64, results map[string][]wire.NodeValue) error {
	var nodes []wire.Node
	for key, values := range results {
		for _, v := range values {
			n := s.sess.server.Tree.AppendUnder(s.resultsNode, key, v)
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
