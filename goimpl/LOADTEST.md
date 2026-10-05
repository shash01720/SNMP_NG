# Load test: NodeTree against the OpenTelemetry Collector

An attempt to put numbers on how NodeTree compares with the OpenTelemetry
Collector as a data-moving process, using the Collector's own load-test
harness (the testbed in `opentelemetry-collector-contrib`). Read the
[caveats](#caveats-read-these-before-quoting-any-number) first: this compares
two things built for different jobs, once, on one laptop.

**Short version.** Measured at the same number of data points per second, the
current NodeTree reference server uses roughly **6-10x** the CPU of the
Collector when it only ingests, about **30x** when one `onChange` subscriber
is attached at 10,000 points/s, and it **cannot sustain** 70,000 points/s with a
subscriber or 210,000 ingest-only, where the Collector delivered every point.
Some of that is the implementation (three defects found and fixed along the
way, more listed below); some is the protocol (a request must fit one
datagram, so 25 points per request against the Collector's 700).

## What was measured

**OpenTelemetry Collector** -- the testbed's `TestMetric10kDPS` scenario shape:
a load generator sends OTLP/gRPC metrics to a Collector child process
(`GOMAXPROCS=2`, receiver -> batch -> exporter), which forwards to a mock
backend; the run only passes if every item sent is received. Two things about
that harness are easy to get wrong:

- "10kDPS" counts **metrics**, and the provider emits **7 data points per
  metric**, so the stock test really offers about **70,000 data points/s**
  (1,050,700 points in 15 s). The numbers below are all in data points per
  second, so they can be compared.
- Each OTLP data point carries a metric name, description, unit, two
  attributes and two timestamps. A NodeTree point carries a key and a
  `Counter64`, nothing else. Per point, NodeTree is moving **less**
  information, which flatters it.

The Collector was `cmd/oteltestbedcol` built from the contrib checkout at
commit `7450f66`. To get rates other than the stock one, a variant of the
testbed's scenario takes the rate from an environment variable (listed under
"Reproducing").

**NodeTree** -- there is no collector component, so `cmd/loadtest` makes the
reference server play that role: it starts `cmd/server` as a child process
(`GOMAXPROCS=2`), builds 1,000 metric series under `/config/metrics/<host>/<metric>`
through the protocol itself (staged `Create`, one `Set` with `newParent`),
offers data points at a fixed open-loop rate as batched `Set`s (25 points per
`Set`, the most that fits one datagram), and optionally attaches `onChange`
subscribers over every series (transfer interval 1 s) that follow
continuation pointers like a real client. CPU is the server process's
cumulative CPU time (user + system) sampled each second; memory is its RSS.
"Accepted" is points whose `Set` was acknowledged; "delivered" is leaf updates
the subscriber received.

All runs: 15 s of load, Apple silicon laptop, macOS, load generators and
server on the same machine, one run per cell.

## Results

### OpenTelemetry Collector (OTLP/gRPC)

| offered data points/s | delivered | CPU avg / max % | RAM avg / max MiB | CPU% per 1k pts/s |
|---:|---:|---|---|---:|
| ~10,000 (1.43k metrics/s) | 150,500 / 150,500 (100%) | 5.0 / 64.9 | 66 / 96 | 0.5 |
| ~70,000 (10k metrics/s) | 1,050,700 / 1,050,700 (100%) | 19.5 / 128.2 | 69 / 97 | 0.28 |
| ~210,000 (30k metrics/s) | 3,151,400 / 3,151,400 (100%) | 35.5 / 84.9 | 70 / 100 | 0.17 |

(The stock `TestMetric10kDPS/OTLP` run, a separate execution of the middle row,
gave 16.2 / 20.3 CPU and 56 / 90 MiB, so expect a few points of run-to-run
spread.) The testbed does not report per-request latency.

### NodeTree

#### After (the numbers used in the comparison)

| offered pts/s | subscribers | accepted pts/s | % of offered | delivered / accepted | ack p50 / p99 | CPU avg / max % | RSS avg / max MiB | CPU% per 1k accepted pts/s |
|---:|---:|---:|---:|---:|---|---|---|---:|
| 10,000 | 0 | 10,001 | 100% | n/a | 1.01ms / 2.81ms | 47.9 / 52.6 | 46 / 67 | 4.8 |
| 70,000 | 0 | 70,001 | 100% | n/a | 1.63ms / 31.1ms | 125.8 / 327.5 | 227 / 396 | 1.8 |
| 210,000 | 0 | 73,254 | 35% | n/a | 193.09ms / 2.13598s | 157.1 / 220.3 | 235 / 391 | 2.1 |
| 10,000 | 1 | 10,001 | 100% | 100% | 1.98ms / 12.65ms | 158.7 / 166.2 | 117 / 190 | 15.9 |
| 30,000 | 1 | 20,423 | 68% | 99% | 162.11ms / 1.66052s | 176.4 / 181.1 | 179 / 295 | 8.6 |
| 50,000 | 1 | 28,967 | 58% | 90% | 236.09ms / 2.21501s | 180.7 / 266.7 | 230 / 368 | 6.2 |
| 70,000 | 1 | 27,402 | 39% | 89% | 269.08ms / 2.38927s | 182.5 / 398.3 | 212 / 341 | 6.7 |


Reading it: up to 10,000 points/s NodeTree keeps up and, with a subscriber,
delivers every update. Beyond that it saturates its two cores. Ingest-only it
holds 70,000 points/s but tops out near 73,000; with one subscriber it tops
out between 20,000 and 29,000, after which unacknowledged requests pile up
(an ack p99 of about 2 s at saturation reflects queueing plus the client's
retransmits, which give up after 2 s; it is not a service time).

### Side by side, at equal data-point rates

| offered pts/s | Collector CPU avg | NodeTree ingest-only | NodeTree + 1 subscriber |
|---:|---:|---|---|
| 10,000 | 5.0% | 47.9% (~10x), all accepted | 158.7% (~32x), all accepted and delivered |
| 70,000 | 19.5% | 125.8% (~6.5x), all accepted | not sustained (39% accepted) |
| 210,000 | 35.5% | not sustained (35% accepted) | not run |

Memory is the other difference: the Collector holds flat around 70 MiB;
NodeTree's RSS climbs with load (peaks of 190 MiB at 10,000 points/s with a
subscriber, about 390 MiB at 70,000 ingest-only). Two things in the design
would produce that: replies are cached for 30 s to answer retransmits, and
every query push is kept in session state until the query is cancelled (a
known gap). I have not isolated how much each contributes.

## Caveats (read these before quoting any number)

- **Different jobs.** The Collector moves an event stream: every data point
  arrives, in order, unmodified. NodeTree moves *state*: a `Set` writes a new
  value, and an `onChange` subscriber is told what changed. Under load a
  subscriber may be shown fewer updates than were written (about 90% at
  the rates where the server was saturated), because a wake-up samples current
  values rather than replaying every write. That is by design, not a bug, but
  it means "delivered" is not the same promise the Collector makes.
- **A query push does not say which node a value came from.** Each pushed
  leaf is keyed by the node's own key, so with ten hosts all reporting `m0042`
  the subscriber cannot tell them apart except by position. The benchmark
  counts deliveries and ignores this; a real telemetry consumer could not.
  This is a gap in the result model, not in the load test (see
  `CapabilityMatrix.md`).
- **Not the same pipeline.** The Collector is receiver -> processor ->
  exporter -> backend, two network hops. NodeTree here is one process acting
  as store and forwarder; there is no exporter, queue or retry.
- **Batching is a protocol difference.** NodeTree sends 25 points per request
  (a request must fit one datagram, about 1.2 KB), so 70,000 points/s is 2,800
  requests/s. The Collector's generator sends 700 points per request, about
  100 requests/s. That gap is inherent to the design, not tuning.
- **One run per cell, one machine, 15 s.** No repetitions or confidence
  intervals; the two Collector runs of the same scenario differ by ~3 CPU
  points. Treat the figures as orders of magnitude. CPU can exceed 200% with
  `GOMAXPROCS=2` because garbage-collector and syscall threads do not count
  against it.
- **This measures the reference implementation, not an optimised one.** The
  list below is what is known to be inefficient; none of it has been tuned.

## What the load test found in NodeTree

Three defects, all fixed in this change (each has a regression test):

1. **`onChange` conflated nodes that share a key.** Change detection was
   keyed on a node's key alone, so ten hosts' `m0042` looked like one value
   that kept changing, and the server pushed continuously. It now diffs by a
   per-node identity assigned at creation. (The node's key path is not an
   identity here either: repeated sibling keys are how arrays are
   represented, so the demo tree's two users are both `/users/user`. My first
   fix used the path and was caught by an end-to-end test.)
2. **Fitting a push into datagrams was quadratic.** `FitToSize` tried every
   window size from the whole result downward, re-marshalling a large window
   each time, and every continuation fetch repeated it: 103 ms for a
   1,000-node result and 1.76 s for 4,000, per call. It now binary-searches
   (1.8 ms and 3.5 ms), and a test checks it chooses the same window as the
   exhaustive search across flat and deep trees and many budgets.
3. **Expiring the response cache scanned the whole map on every insert**, a
   bug introduced when the cache was first bounded. At 2,800 requests/s with a
   30 s TTL that is ~84,000 entries per request, under the cache lock. Expiry is
   now a FIFO. At 70,000 points/s ingest-only this took p99 ack latency from
   88 ms to 31 ms and CPU from 153% to 126%.

Known costs not yet addressed (from profiles, or by inspection where noted):

- Every request recompiles its regular expressions (by inspection).
- The access check builds a full path string for each candidate node even in
  open mode (`NodePath` in the profile).
- Integer encoding goes through `math/big` (in the profile).
- Each wake-up of an `onChange` query re-samples every series it watches;
  cost scales with series count times subscribers, not with what changed.
- A continuation fetch re-flattens the whole push to cut one window (by
  inspection), so a large push costs more than linear in its size to deliver.
- One global lock around the tree.
- Memory: replies cached for 30 s, and query pushes retained forever (see
  above; their shares are unmeasured).

## Reproducing

NodeTree:

```bash
cd goimpl
go build -o /tmp/nt-server ./cmd/server
go build -o /tmp/nt-loadtest ./cmd/loadtest
/tmp/nt-loadtest -server /tmp/nt-server -dps 10000 -subscribers 1 -duration 15s
# use -generators 2..4 for 70,000+ points/s; see -h for the rest
```

`cmd/loadtest` samples the server with `ps -o time=,rss=`, which is accurate to
about 10 ms on macOS; on Linux `ps` reports whole seconds of CPU time, which
makes the per-second CPU figure coarse.

OpenTelemetry Collector (needs the contrib checkout, roughly 140 MB at depth 1,
plus Go modules):

```bash
git clone --depth 1 https://github.com/open-telemetry/opentelemetry-collector-contrib.git
cd opentelemetry-collector-contrib
make oteltestbedcol                      # builds bin/oteltestbedcol_<os>_<arch>
# add the scenario below as testbed/tests/cmp_rate_test.go, then:
cd testbed/tests
CGO_ENABLED=0 RUN_TESTBED=1 TESTCASE_DURATION=15s CMP_ITEMS_PER_SEC=10000 \
  go test -count=1 -run 'TestCompareOTLPRate$' .
# results: testbed/tests/results/TESTRESULTS.md
```

`CGO_ENABLED=0` is what the Collector's own Makefile uses for the binary; it
was also needed for the test binary here, whose cgo link failed against this
machine's macOS SDK. `CMP_ITEMS_PER_SEC` is in **metrics**; multiply by 7 for
data points. This is the stock `Scenario10kItemsPerSecond` with the rate
parameterised:

```go
package tests

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/common/testutil"
	"github.com/open-telemetry/opentelemetry-collector-contrib/testbed/testbed"
)

// TestCompareOTLPRate is Scenario10kItemsPerSecond with the offered rate taken
// from CMP_ITEMS_PER_SEC (items are METRICS; the provider emits 7 data points
// per metric), everything else identical, so OTLP/gRPC can be measured at the
// same data-point rates as the NodeTree load test.
func TestCompareOTLPRate(t *testing.T) {
	rate, _ := strconv.Atoi(os.Getenv("CMP_ITEMS_PER_SEC"))
	if rate == 0 {
		t.Skip("CMP_ITEMS_PER_SEC not set")
	}
	sender := testbed.NewOTLPMetricDataSender(testbed.DefaultHost, testutil.GetAvailablePort(t))
	receiver := testbed.NewOTLPDataReceiver(testutil.GetAvailablePort(t))

	resultDir, err := filepath.Abs(path.Join("results", t.Name()))
	require.NoError(t, err)
	loadOptions := &testbed.LoadOptions{ItemsPerBatch: 100, Parallel: 1, DataItemsPerSecond: rate}

	agentProc := testbed.NewChildProcessCollector(testbed.WithEnvVar("GOMAXPROCS", "2"))
	configStr := createConfigYaml(t, sender, receiver, resultDir, nil, nil)
	configCleanup, err := agentProc.PrepareConfig(t, configStr)
	require.NoError(t, err)
	defer configCleanup()

	tc := testbed.NewTestCase(t, testbed.NewPerfTestDataProvider(*loadOptions), sender, receiver, agentProc,
		&testbed.PerfTestValidator{}, performanceResultsSummary,
		testbed.WithResourceLimits(testbed.ResourceSpec{ExpectedMaxCPU: 1000, ExpectedMaxRAM: 4000}))
	t.Cleanup(tc.Stop)

	tc.StartBackend()
	tc.StartAgent()
	tc.StartLoad(*loadOptions)
	tc.WaitFor(func() bool { return tc.LoadGenerator.DataItemsSent() > 0 }, "load generator started")
	tc.Sleep(tc.Duration)
	tc.StopLoad()
	tc.WaitFor(func() bool { return tc.LoadGenerator.DataItemsSent() == tc.MockBackend.DataItemsReceived() }, "all data items received")
	tc.ValidateData()
}
```

## Before the cache fix

The same NodeTree runs before the response-cache expiry fix (the fitting and
identity fixes were already in), kept for comparison:

#### Before the response-cache expiry fix

| offered pts/s | subscribers | accepted pts/s | % of offered | delivered / accepted | ack p50 / p99 | CPU avg / max % | RSS avg / max MiB | CPU% per 1k accepted pts/s |
|---:|---:|---:|---:|---:|---|---|---|---:|
| 10,000 | 0 | 10,001 | 100% | n/a | 940µs / 2.99ms | 49.0 / 52.5 | 45 / 66 | 4.9 |
| 70,000 | 0 | 70,001 | 100% | n/a | 7.59ms / 87.74ms | 152.7 / 381.6 | 227 / 389 | 2.2 |
| 210,000 | 0 | 69,548 | 33% | n/a | 202.79ms / 2.24347s | 163.6 / 211.6 | 221 / 366 | 2.4 |
| 10,000 | 1 | 10,001 | 100% | 100% | 2.05ms / 12.39ms | 159.6 / 167.0 | 112 / 188 | 16.0 |
| 30,000 | 1 | 17,934 | 60% | 99% | 188.91ms / 1.89953s | 176.6 / 353.9 | 166 / 253 | 9.8 |
| 50,000 | 1 | 25,380 | 51% | 92% | 270.16ms / 2.36536s | 180.7 / 185.1 | 210 / 344 | 7.1 |
| 70,000 | 1 | 25,798 | 37% | 90% | 289.57ms / 2.51329s | 183.0 / 288.5 | 207 / 327 | 7.1 |


