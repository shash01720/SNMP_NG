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
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/shash01720/SNMP_NG/goimpl/internal/authz"
	"github.com/shash01720/SNMP_NG/goimpl/internal/certs"
	"github.com/shash01720/SNMP_NG/goimpl/internal/query"
	"github.com/shash01720/SNMP_NG/goimpl/internal/reliability"
	"github.com/shash01720/SNMP_NG/goimpl/internal/tree"
	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
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

	// Policy is the access-control policy applied to every session. nil is
	// open mode: identity-based rules don't apply, but the built-in session
	// protections (see internal/authz) always do.
	Policy *authz.Policy
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

	// identity is the peer's verified certificate CommonName, or
	// "anonymous" if it presented none (only possible when the server
	// doesn't require client certificates). auth answers every access check
	// made on this session's behalf.
	identity string
	auth     authz.Checker

	newNodesPath     *tree.Node
	errorsPath       *tree.Node
	queryResultsPath *tree.Node

	sender   *reliability.Sender
	receiver *reliability.Receiver

	seqMu   sync.Mutex
	nextSeq int64

	respCacheMu sync.Mutex
	respCache   map[int64]cachedResponse // keyed by the request's own sequenceNumber
	respOrder   []respRecord             // insertion order of respCache, for expiry
	respHead    int                      // first live record in respOrder

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
	identity := certs.PeerIdentity(conn.ConnectionState().TLS)
	if identity == "" {
		identity = "anonymous"
	}
	sess := &Session{
		ID:               id,
		identity:         identity,
		auth:             s.Policy.NewChecker(identity, id),
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

	log.Printf("[server] session %s: connected (%s) as %q", sess.ID, sess.conn.RemoteAddr(), sess.identity)
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

// cacheResponse records resp for answering a retransmitted request, and
// expires entries older than respCacheTTL.
func (sess *Session) cacheResponse(requestSeq int64, resp *wire.Response) {
	sess.cacheResponseAt(requestSeq, resp, time.Now())
}

// respRecord is one insertion, in insertion order, so expiry only ever looks
// at the oldest entries instead of scanning the whole map.
type respRecord struct {
	seq int64
	at  time.Time
}

// cacheResponseAt is cacheResponse with the clock supplied. Expiry is a FIFO
// over insertion order: an entry is dropped from the map only if it is still
// the one that insertion put there (a sequence number cached twice keeps its
// newer entry), and the queue is compacted once most of it is spent. The
// first version scanned the entire map on every insert, which is O(entries
// held) per request -- about 84,000 at 2,800 requests/s with a 30 s TTL --
// and was the largest CPU cost in a load test.
func (sess *Session) cacheResponseAt(requestSeq int64, resp *wire.Response, now time.Time) {
	sess.respCacheMu.Lock()
	defer sess.respCacheMu.Unlock()
	sess.respCache[requestSeq] = cachedResponse{resp: resp, at: now}
	sess.respOrder = append(sess.respOrder, respRecord{requestSeq, now})
	for sess.respHead < len(sess.respOrder) {
		old := sess.respOrder[sess.respHead]
		if now.Sub(old.at) <= respCacheTTL {
			break
		}
		if c, ok := sess.respCache[old.seq]; ok && c.at.Equal(old.at) {
			delete(sess.respCache, old.seq)
		}
		sess.respOrder[sess.respHead] = respRecord{}
		sess.respHead++
	}
	if sess.respHead >= 1024 && sess.respHead*2 >= len(sess.respOrder) {
		n := copy(sess.respOrder, sess.respOrder[sess.respHead:])
		sess.respOrder = sess.respOrder[:n]
		sess.respHead = 0
	}
}

// sendFittedNodes sends flat[resumeIndex:] as a Response to requestSeq,
// fitting it into one QUIC datagram. If the full remainder doesn't fit, it
// is truncated via tree.FitToSize (rewriting the offset pointer(s) that
// would have reached past the cut into an absolute
// "<baseExpression>@<index>" continuation pointer the client can Get to
// resume) -- see node.asn's NodePointer docs.
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
// cache says whether to remember the response for answering a retransmitted
// request (respCache). A Query's pushes pass false: they share inReplyTo
// with the query's registration ack, and caching one would replace the ack
// a retransmitted Query request is supposed to get back.
func (sess *Session) sendFittedNodes(requestSeq int64, flat []wire.Node, resumeIndex int, baseExpression string, cache bool) {
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
		if len(fitted) == 0 {
			// Not even one node plus a continuation pointer fits. Sending
			// the empty window would look to the client like "no match" --
			// silently dropped data -- so send nothing, as the
			// DatagramTooLargeError path below does.
			log.Printf("[server] session %s: cannot fit even one node within max datagram size %d for request seq %d",
				sess.ID, cached, requestSeq)
			return
		}
		nodes = fitted
	}

	for attempt := 0; attempt < 2; attempt++ {
		resp := build(nodes)
		payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgResponse, Response: resp})

		err := sess.sender.Send(txSeq, payload)
		if err == nil {
			if cache {
				sess.cacheResponse(requestSeq, resp)
			}
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
	errPermissionDenied  = "PermissionDenied"
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

// errCode picks the error node code for err: PermissionDenied if an access
// check refused it, otherwise the operation's own generic code.
func errCode(err error, generic string) string {
	if errors.Is(err, tree.ErrPermissionDenied) {
		return errPermissionDenied
	}
	return generic
}

// --- Get -----------------------------------------------------------------

func (sess *Session) handleGet(g *wire.Get) {
	if g.Target.Kind != wire.PointerAbsolute {
		sess.respondError(g.SequenceNumber, errInvalidExpression, "Get.target must be an absolute expression")
		return
	}
	flat, resumeIndex, base, err := sess.server.Tree.GetFullAs(g.Target.Absolute, sess.auth)
	if err != nil {
		sess.respondError(g.SequenceNumber, errInvalidExpression, err.Error())
		return
	}
	sess.sendFittedNodes(g.SequenceNumber, flat, resumeIndex, base, true)
}

// --- Set -------------------------------------------------------------------

func (sess *Session) handleSet(s *wire.Set) {
	touched, err := sess.server.Tree.SetAs(s, sess.newNodesPath, sess.auth)
	if err != nil {
		// Set's edits can each fail for a different reason (bad expression,
		// wrong match count, a relink conflict between two edits), so
		// there's no single more-specific code worth guessing at here the
		// way handleGet's errInvalidExpression can be -- errInvalidSet plus
		// the message (which names the offending target) is what a caller
		// actually needs.
		sess.respondError(s.SequenceNumber, errCode(err, errInvalidSet), err.Error())
		return
	}
	sess.reapCancelledQueries()
	sess.respondAndCache(s.SequenceNumber, &wire.Response{
		InReplyTo: s.SequenceNumber,
		Nodes:     sess.server.Tree.Snapshot(touched),
	})
}

// --- Delete ------------------------------------------------------------------

func (sess *Session) handleDelete(d *wire.Delete) {
	deleted, err := sess.server.Tree.DeleteAs(d.Targets, sess.auth)
	if err != nil {
		sess.respondError(d.SequenceNumber, errCode(err, errInvalidDelete), err.Error())
		return
	}
	sess.reapCancelledQueries()
	sess.respondAndCache(d.SequenceNumber, &wire.Response{
		InReplyTo: d.SequenceNumber,
		Nodes:     sess.server.Tree.Snapshot(deleted),
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
	n, err := sess.server.Tree.CreateStagedAs(sess.newNodesPath, parentExpr, c.Key, value, sess.auth)
	if err != nil {
		sess.respondError(c.SequenceNumber, errInvalidCreate, err.Error())
		return
	}
	sess.respondAndCache(c.SequenceNumber, &wire.Response{
		InReplyTo: c.SequenceNumber,
		Nodes:     sess.server.Tree.Snapshot([]*tree.Node{n}),
	})
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

	runner := query.NewRunner(*q, treeSampler{tree: sess.server.Tree, auth: sess.auth}, &sessionResultSink{
		sess:        sess,
		resultsNode: resultsNode,
		resultsPath: fmt.Sprintf("/Sessions/Connection-ID\\=%s/QueryResults/Query-SequenceNumber\\=%d", sess.ID, q.SequenceNumber),
	})

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

type treeSampler struct {
	tree *tree.Tree
	auth authz.Checker
}

func (s treeSampler) Sample(expression string) ([]query.Sample, error) {
	sampled, err := s.tree.SampleAs(expression, s.auth)
	if err != nil {
		return nil, err
	}
	samples := make([]query.Sample, len(sampled))
	for i, n := range sampled {
		samples[i] = query.Sample{ID: strconv.FormatUint(n.ID, 10), Key: n.Key, Value: n.Value}
	}
	return samples, nil
}

// ChangedSince implements query.ChangeWaiter, letting a CollectOnChange
// Runner block on the live tree's own mutations instead of polling.
func (s treeSampler) ChangedSince(since uint64) (<-chan struct{}, uint64) {
	return s.tree.ChangedSince(since)
}

// sessionResultSink delivers one query's results. Each transfer is
// materialized as a new subtree under the query's own resultsNode, rooted at
// a node keyed by the transfer's timestamp with the results as its leaf
// children, and that same subtree is what is pushed to the client (see
// node.asn's SESSION PATHS docs). Scoping it under resultsNode is what lets
// Delete target one query's results, and thereby cancel it, without
// disturbing any other active query in the session.
type sessionResultSink struct {
	sess        *Session
	resultsNode *tree.Node
	resultsPath string // expression for resultsNode, for continuation pointers

	mu     sync.Mutex
	lastTS time.Time
}

// timestampKeyFormat is fixed-width, UTC and nanosecond-precise, so keys sort
// lexicographically in time order and contain nothing the expression grammar
// treats specially ("/", "=", "@" or "\").
const timestampKeyFormat = "2006-01-02T15:04:05.000000000Z"

// nextTimestamp returns the current time, forced strictly later than the
// previous one this sink handed out so two transfers can never share a key:
// the continuation expression for a truncated push names its subtree by that
// key, and must not match two of them.
func (s *sessionResultSink) nextTimestamp() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := time.Now().UTC()
	if !ts.After(s.lastTS) {
		ts = s.lastTS.Add(time.Nanosecond)
	}
	s.lastTS = ts
	return ts
}

// sortedEntries flattens results into tree entries ordered by key (a map
// iterates in random order), keeping each key's values in collection order.
func sortedEntries(results map[string][]wire.NodeValue) []tree.Entry {
	keys := make([]string, 0, len(results))
	for k := range results {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var entries []tree.Entry
	for _, k := range keys {
		for _, v := range results[k] {
			entries = append(entries, tree.Entry{Key: k, Value: v})
		}
	}
	return entries
}

func (s *sessionResultSink) DeliverResults(querySeq int64, results map[string][]wire.NodeValue) error {
	entries := sortedEntries(results)
	if len(entries) == 0 {
		return nil // nothing to push this transfer
	}
	key := s.nextTimestamp().Format(timestampKeyFormat)
	flat := s.sess.server.Tree.AppendLeafSubtree(s.resultsNode, key, entries)
	s.sess.sendFittedNodes(querySeq, flat, 0, s.resultsPath+"/"+key, false)
	return nil
}
