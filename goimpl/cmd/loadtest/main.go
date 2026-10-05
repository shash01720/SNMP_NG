// Command loadtest measures a NodeTree server as an ingest-and-forward node,
// in the style of the OpenTelemetry Collector testbed's load tests: it starts
// the server binary as a child process (GOMAXPROCS=2), offers data points at a
// fixed rate, optionally attaches onChange subscribers that receive them, and
// reports the server process's CPU and memory alongside what was accepted and
// delivered.
//
// A "data point" is one edit in a Set: a new value for one metric series that
// lives in the tree. The series are created through the protocol itself
// (staged Create, then one Set with newParent), so the tool uses nothing a
// real client couldn't.
//
//	go build -o /tmp/server ./cmd/server
//	go run ./cmd/loadtest -server /tmp/server -dps 10000 -subscribers 1
//
// What it can and can't tell you is in goimpl/LOADTEST.md; the short version
// is that NodeTree moves state (the latest value of each series), not an
// event stream, so "delivered" is not expected to equal "offered".
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/shash01720/SNMP_NG/goimpl/internal/certs"
	"github.com/shash01720/SNMP_NG/goimpl/internal/reliability"
	"github.com/shash01720/SNMP_NG/goimpl/internal/wire"
)

const (
	retransmitInterval = 250 * time.Millisecond
	maxRetransmits     = 8
	ackInterval        = 100 * time.Millisecond
	requestTimeout     = 5 * time.Second
)

// --- minimal client --------------------------------------------------------

type handler struct {
	fn         func(*wire.Response)
	persistent bool
}

type client struct {
	conn     *quic.Conn
	sender   *reliability.Sender
	receiver *reliability.Receiver
	seq      atomic.Int64

	mu       sync.Mutex
	handlers map[int64]handler
}

func dial(ctx context.Context, addr string) (*client, error) {
	conn, err := quic.DialAddr(ctx, addr, certs.ClientConfig(), &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	c := &client{conn: conn, handlers: map[int64]handler{}}
	c.sender = reliability.NewSender(func(p []byte) error { return conn.SendDatagram(p) },
		retransmitInterval, maxRetransmits, func(int64) {})
	c.receiver = reliability.NewReceiver()
	go c.sender.RunRetransmitLoop(ctx)
	go c.readLoop(ctx)
	go c.ackLoop(ctx)
	return c, nil
}

func (c *client) readLoop(ctx context.Context) {
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
				c.dispatch(msg.Response)
			}
		case wire.MsgSummaryAck:
			c.sender.HandleAck(msg.SummaryAck)
		}
	}
}

func (c *client) ackLoop(ctx context.Context) {
	t := time.NewTicker(ackInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ack := c.receiver.BuildAck(); len(ack.Received) > 0 {
				_ = c.conn.SendDatagram(wire.MarshalMessage(wire.Message{Kind: wire.MsgSummaryAck, SummaryAck: ack}))
			}
		}
	}
}

func (c *client) dispatch(r *wire.Response) {
	c.mu.Lock()
	h, ok := c.handlers[r.InReplyTo]
	if ok && !h.persistent {
		delete(c.handlers, r.InReplyTo)
	}
	c.mu.Unlock()
	if ok {
		h.fn(r)
	}
}

func (c *client) on(seq int64, fn func(*wire.Response), persistent bool) {
	c.mu.Lock()
	c.handlers[seq] = handler{fn, persistent}
	c.mu.Unlock()
}

// request sends the message build(seq) and waits for its response.
func (c *client) request(build func(seq int64) wire.Message) (*wire.Response, error) {
	seq := c.seq.Add(1)
	ch := make(chan *wire.Response, 1)
	c.on(seq, func(r *wire.Response) { ch <- r }, false)
	if err := c.sender.Send(seq, wire.MarshalMessage(build(seq))); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		if r.Error {
			return r, fmt.Errorf("server returned an error response")
		}
		return r, nil
	case <-time.After(requestTimeout):
		return nil, fmt.Errorf("timeout waiting for seq %d", seq)
	}
}

func (c *client) get(expr string) (*wire.Response, error) {
	return c.request(func(seq int64) wire.Message {
		return wire.Message{Kind: wire.MsgGet, Get: &wire.Get{SequenceNumber: seq, Target: wire.AbsolutePointer(expr)}}
	})
}

// --- bootstrap -------------------------------------------------------------

func hostKey(h int) string   { return fmt.Sprintf("h%03d", h) }
func metricKey(m int) string { return fmt.Sprintf("m%04d", m) }
func seriesPath(h, m int) string {
	return "/config/metrics/" + hostKey(h) + "/" + metricKey(m)
}

// bootstrap builds /config/metrics/<host>/<metric> through the protocol:
// stage the whole subtree under this session's NewNodes, then attach it to
// live config with a single Set carrying newParent.
func bootstrap(c *client, hosts, perHost int) error {
	r, err := c.get("/Sessions/Connection-ID.*")
	if err != nil || len(r.Nodes) == 0 {
		return fmt.Errorf("finding own session: %v", err)
	}
	staging := "/Sessions/" + strings.ReplaceAll(r.Nodes[0].Key, "=", `\=`) + "/NewNodes"

	create := func(key string, v *wire.NodeValue, parent string) error {
		_, err := c.request(func(seq int64) wire.Message {
			cr := &wire.Create{SequenceNumber: seq, Key: key, Value: v}
			if parent != "" {
				cr.Parent = &parent
			}
			return wire.Message{Kind: wire.MsgCreate, Create: cr}
		})
		return err
	}
	if err := create("metrics", nil, ""); err != nil {
		return err
	}
	zero := wire.Counter64Value(0)
	for h := 0; h < hosts; h++ {
		if err := create(hostKey(h), nil, staging+"/metrics"); err != nil {
			return err
		}
		for m := 0; m < perHost; m++ {
			if err := create(metricKey(m), &zero, staging+"/metrics/"+hostKey(h)); err != nil {
				return err
			}
		}
	}
	dest := "/config"
	_, err = c.request(func(seq int64) wire.Message {
		return wire.Message{Kind: wire.MsgSet, Set: &wire.Set{SequenceNumber: seq, Edits: []wire.SetEdit{
			{Target: staging + "/metrics", NewParent: &dest},
		}}}
	})
	return err
}

// --- the server under test -------------------------------------------------

type proc struct {
	cmd *exec.Cmd
	pid int
}

func startServer(bin, logPath string) (*proc, string, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	cmd := exec.Command(bin, "-addr", addr)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	if logPath != "" {
		f, err := os.Create(logPath)
		if err != nil {
			return nil, "", err
		}
		cmd.Stdout, cmd.Stderr = f, f
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		c, err := dial(ctx, addr)
		cancel()
		if err == nil {
			c.conn.CloseWithError(0, "")
			return &proc{cmd, cmd.Process.Pid}, addr, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd.Process.Kill()
	return nil, "", fmt.Errorf("server never became ready on %s", addr)
}

func (p *proc) stop() {
	p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		p.cmd.Process.Kill()
	}
}

// parseCPUTime parses ps's cumulative CPU time: "M:SS.ss", "H:MM:SS.ss" or
// "D-HH:MM:SS".
func parseCPUTime(s string) (float64, error) {
	days := 0.0
	if i := strings.Index(s, "-"); i >= 0 {
		d, err := strconv.Atoi(s[:i])
		if err != nil {
			return 0, err
		}
		days = float64(d)
		s = s[i+1:]
	}
	total := 0.0
	for _, part := range strings.Split(s, ":") {
		f, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, err
		}
		total = total*60 + f
	}
	return total + days*86400, nil
}

type sample struct {
	at     time.Time
	cpuSec float64
	rssMiB float64
}

func (p *proc) sample() (sample, error) {
	out, err := exec.Command("ps", "-o", "time=,rss=", "-p", strconv.Itoa(p.pid)).Output()
	if err != nil {
		return sample{}, err
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return sample{}, fmt.Errorf("unexpected ps output %q", out)
	}
	cpu, err := parseCPUTime(f[0])
	if err != nil {
		return sample{}, err
	}
	rss, err := strconv.ParseFloat(f[1], 64)
	if err != nil {
		return sample{}, err
	}
	return sample{time.Now(), cpu, rss / 1024}, nil
}

// --- load ------------------------------------------------------------------

type stats struct {
	sent, applied, errored atomic.Int64
	latMu                  sync.Mutex
	lat                    []time.Duration
}

func (s *stats) addLatency(d time.Duration) {
	s.latMu.Lock()
	s.lat = append(s.lat, d)
	s.latMu.Unlock()
}

func (s *stats) percentile(p float64) time.Duration {
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if len(s.lat) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), s.lat...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[int(float64(len(sorted)-1)*p)]
}

// generator offers points at its share of the rate: every interval it sends
// one Set of `batch` edits, round-robin over the series, catching up if it
// falls behind so the offered rate holds (open loop: it never waits for
// replies).
func generator(c *client, id, gens, hosts, perHost, batch int, interval time.Duration, deadline time.Time, st *stats, late *atomic.Int64) {
	n := hosts * perHost
	cursor := (id * n) / gens
	var counter int64
	next := time.Now().Add(time.Duration(id) * interval / time.Duration(gens))
	for time.Now().Before(deadline) {
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		} else if -d > interval {
			late.Add(1)
		}
		next = next.Add(interval)

		edits := make([]wire.SetEdit, batch)
		for i := range edits {
			idx := cursor % n
			cursor++
			counter++
			v := wire.Counter64Value(uint64(counter))
			edits[i] = wire.SetEdit{Target: seriesPath(idx/perHost, idx%perHost), NewValue: &v}
		}
		seq := c.seq.Add(1)
		started := time.Now()
		c.on(seq, func(r *wire.Response) {
			st.addLatency(time.Since(started))
			if r.Error {
				st.errored.Add(int64(batch))
			} else {
				st.applied.Add(int64(batch))
			}
		}, false)
		payload := wire.MarshalMessage(wire.Message{Kind: wire.MsgSet, Set: &wire.Set{SequenceNumber: seq, Edits: edits}})
		if err := c.sender.Send(seq, payload); err != nil {
			st.errored.Add(int64(batch))
			continue
		}
		st.sent.Add(int64(batch))
	}
}

// subscriber attaches one onChange query over every series and counts the
// leaf updates delivered, following continuation pointers the way a real
// client has to for any push that doesn't fit one datagram.
type subscriber struct {
	c         *client
	delivered atomic.Int64
	pushes    atomic.Int64
	getErrs   atomic.Int64
	wg        sync.WaitGroup
}

func lastAbsolute(nodes []wire.Node) string {
	ptr := ""
	for _, n := range nodes {
		for _, p := range []wire.NodePointer{n.FirstChild, n.NextSibling} {
			if p.Kind == wire.PointerAbsolute {
				ptr = p.Absolute
			}
		}
	}
	return ptr
}

func (s *subscriber) follow(ptr string) {
	defer s.wg.Done()
	for ptr != "" {
		r, err := s.c.get(ptr)
		if err != nil {
			s.getErrs.Add(1)
			return
		}
		s.delivered.Add(int64(len(r.Nodes)))
		ptr = lastAbsolute(r.Nodes)
	}
}

func subscribe(c *client, transfer int64) (*subscriber, error) {
	s := &subscriber{c: c}
	seq := c.seq.Add(1)
	ack := make(chan struct{}, 1)
	c.on(seq, func(r *wire.Response) {
		if len(r.Nodes) == 0 {
			select {
			case ack <- struct{}{}:
			default:
			}
			return
		}
		s.pushes.Add(1)
		s.delivered.Add(int64(len(r.Nodes) - 1)) // minus the timestamp root
		if ptr := lastAbsolute(r.Nodes); ptr != "" {
			s.wg.Add(1)
			go s.follow(ptr)
		}
	}, true)
	q := &wire.Query{
		SequenceNumber:   seq,
		NodeExpression:   "/config/metrics/.*/.*",
		CollectionMode:   wire.OnChangeMode(),
		TransferInterval: transfer,
	}
	if err := c.sender.Send(seq, wire.MarshalMessage(wire.Message{Kind: wire.MsgQuery, Query: q})); err != nil {
		return nil, err
	}
	select {
	case <-ack:
	case <-time.After(requestTimeout):
		return nil, fmt.Errorf("query was never acknowledged")
	}
	return s, nil
}

// --- main ------------------------------------------------------------------

func main() {
	serverBin := flag.String("server", "", "path to the nodetree server binary (go build ./cmd/server)")
	dps := flag.Int("dps", 10000, "offered data points per second")
	batch := flag.Int("batch", 25, "data points (edits) per Set; a Set must fit one datagram, so ~25 is near the ceiling")
	gens := flag.Int("generators", 1, "parallel load generators (one connection each)")
	series := flag.Int("series", 1000, "number of metric series")
	hosts := flag.Int("hosts", 10, "series are spread over this many hosts")
	subs := flag.Int("subscribers", 0, "onChange subscribers receiving every series")
	transfer := flag.Int64("transfer", 1, "subscribers' transfer interval, seconds")
	duration := flag.Duration("duration", 15*time.Second, "how long to offer load")
	label := flag.String("name", "", "scenario name for the report line")
	serverLog := flag.String("server-log", "", "write the server's output to this file")
	flag.Parse()
	if *serverBin == "" {
		log.Fatal("-server is required")
	}
	if *series%*hosts != 0 {
		log.Fatal("-series must be a multiple of -hosts")
	}
	perHost := *series / *hosts

	srv, addr, err := startServer(*serverBin, *serverLog)
	if err != nil {
		log.Fatal(err)
	}
	defer srv.stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	boot, err := dial(ctx, addr)
	if err != nil {
		log.Fatal(err)
	}
	t0 := time.Now()
	if err := bootstrap(boot, *hosts, perHost); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	fmt.Printf("bootstrapped %d series in %v\n", *series, time.Since(t0).Round(time.Millisecond))

	var subscribers []*subscriber
	for i := 0; i < *subs; i++ {
		c, err := dial(ctx, addr)
		if err != nil {
			log.Fatal(err)
		}
		s, err := subscribe(c, *transfer)
		if err != nil {
			log.Fatalf("subscribe: %v", err)
		}
		subscribers = append(subscribers, s)
	}
	// Let the subscribers' baseline pushes land so the run measures steady state.
	time.Sleep(time.Duration(*transfer)*time.Second + 500*time.Millisecond)
	for _, s := range subscribers {
		s.wg.Wait()
		s.delivered.Store(0)
		s.pushes.Store(0)
	}

	// Sanity: one Set of `batch` edits must fit a datagram.
	probe := make([]wire.SetEdit, *batch)
	v := wire.Counter64Value(1<<40 + 1)
	for i := range probe {
		probe[i] = wire.SetEdit{Target: seriesPath(*hosts-1, perHost-1), NewValue: &v}
	}
	if sz := len(wire.MarshalMessage(wire.Message{Kind: wire.MsgSet, Set: &wire.Set{SequenceNumber: 1 << 20, Edits: probe}})); sz > 1200 {
		log.Fatalf("a %d-edit Set is %d bytes, over the ~1200-byte datagram budget; lower -batch", *batch, sz)
	}

	var genClients []*client
	for i := 0; i < *gens; i++ {
		c, err := dial(ctx, addr)
		if err != nil {
			log.Fatal(err)
		}
		genClients = append(genClients, c)
	}

	interval := time.Duration(float64(time.Second) * float64(*batch**gens) / float64(*dps))
	st := &stats{}
	var late atomic.Int64
	var samples []sample
	base, err := srv.sample()
	if err != nil {
		log.Fatal(err)
	}
	samples = append(samples, base)

	start := time.Now()
	deadline := start.Add(*duration)
	var wg sync.WaitGroup
	for i, c := range genClients {
		wg.Add(1)
		go func(i int, c *client) {
			defer wg.Done()
			generator(c, i, *gens, *hosts, perHost, *batch, interval, deadline, st, &late)
		}(i, c)
	}
	stopSampling := make(chan struct{})
	var swg sync.WaitGroup
	swg.Add(1)
	go func() {
		defer swg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopSampling:
				return
			case <-t.C:
				if s, err := srv.sample(); err == nil {
					samples = append(samples, s)
				}
			}
		}
	}()
	wg.Wait()
	elapsed := time.Since(start)
	close(stopSampling)
	swg.Wait()
	if s, err := srv.sample(); err == nil {
		samples = append(samples, s)
	}

	// Drain: let outstanding replies and the last pushes arrive.
	time.Sleep(time.Duration(*transfer)*time.Second + 2*time.Second)
	for _, s := range subscribers {
		s.wg.Wait()
	}

	var cpuAvgNum, cpuMax, ramSum, ramMax float64
	for i := 1; i < len(samples); i++ {
		dt := samples[i].at.Sub(samples[i-1].at).Seconds()
		cpu := (samples[i].cpuSec - samples[i-1].cpuSec) / dt * 100
		cpuAvgNum += cpu * dt
		if cpu > cpuMax {
			cpuMax = cpu
		}
	}
	cpuAvg := cpuAvgNum / samples[len(samples)-1].at.Sub(samples[0].at).Seconds()
	for _, s := range samples[1:] {
		ramSum += s.rssMiB
		if s.rssMiB > ramMax {
			ramMax = s.rssMiB
		}
	}
	ramAvg := ramSum / float64(len(samples)-1)

	sent, applied, errored := st.sent.Load(), st.applied.Load(), st.errored.Load()
	var delivered, pushes, getErrs int64
	for _, s := range subscribers {
		delivered += s.delivered.Load()
		pushes += s.pushes.Load()
		getErrs += s.getErrs.Load()
	}
	name := *label
	if name == "" {
		name = fmt.Sprintf("%dk dps, %d sub", *dps/1000, *subs)
	}
	fmt.Printf("\nscenario:   %s (offered %d points/s, %d/Set, %d generator(s), %d series, %d subscriber(s), transfer %ds)\n",
		name, *dps, *batch, *gens, *series, *subs, *transfer)
	fmt.Printf("load:       %v, generators behind schedule %d times\n", elapsed.Round(10*time.Millisecond), late.Load())
	fmt.Printf("sent:       %d points (%.0f/s)\n", sent, float64(sent)/elapsed.Seconds())
	fmt.Printf("applied:    %d points acknowledged ok (%.0f/s), %d errors, %d unanswered\n",
		applied, float64(applied)/elapsed.Seconds(), errored, sent-applied-errored)
	fmt.Printf("ack latency: p50 %v  p99 %v\n", st.percentile(0.5).Round(10*time.Microsecond), st.percentile(0.99).Round(10*time.Microsecond))
	if *subs > 0 {
		fmt.Printf("delivered:  %d leaf updates across %d subscriber(s) in %d pushes (%.0f/s per subscriber, %.0f%% of applied), %d continuation errors\n",
			delivered, *subs, pushes, float64(delivered)/float64(*subs)/elapsed.Seconds(),
			100*float64(delivered)/float64(*subs)/float64(maxI64(applied, 1)), getErrs)
	}
	fmt.Printf("server:     CPU avg %.1f%% max %.1f%% (of one core, GOMAXPROCS=2), RSS avg %.1f MiB max %.1f MiB\n", cpuAvg, cpuMax, ramAvg, ramMax)
	fmt.Printf("| %s | %.0f | %.0f | %d | %d | %.1f | %.1f | %.1f | %.1f |\n", name,
		float64(sent)/elapsed.Seconds(), float64(applied)/elapsed.Seconds(), errored, delivered/int64(maxI(*subs, 1)), cpuAvg, cpuMax, ramAvg, ramMax)
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
