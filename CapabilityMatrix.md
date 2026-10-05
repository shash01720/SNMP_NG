# Capability matrix

How NodeTree compares with SNMP, NETCONF and gNMI, checked against the
current code. Legend: ✅ supported, ⚠️ partial, ❌ not supported, n/a not
applicable to that protocol.

| Capability | SNMP | NETCONF | gNMI | NodeTree |
|---|---|---|---|---|
| Point / bulk read | GET, GETBULK | `<get>` | `Get` | ✅ regex `Get` with server-side truncation and continuation |
| Write | SET | `<edit-config>` | `Set` | ✅ regex-matched, multi-edit, atomic with rollback |
| Delete | RowStatus | `operation="delete"` | `Delete` | ✅ dedicated `Delete`; the server computes the relink; idempotent |
| Replace a subtree | ❌ | ✅ `replace` | ✅ `Replace` | ⚠️ `Set` only merges values. Emulate with `Delete`, staged `Create`s, then `newParent`; there is no one-step replace |
| Create | RowStatus | create op | implicit | ✅ staged and nestable under the session's `NewNodes` |
| Staged / candidate config | ❌ | ✅ candidate + commit | ❌ | ⚠️ New subtrees only: `Create` + `newParent` commits atomically. Edits to existing live values apply immediately |
| Discard staged changes | ❌ | ✅ `discard-changes` | ❌ | ✅ `Delete` on the staged subtree |
| Locking | ❌ | ✅ | ❌ | ❌ |
| Schema / validation | MIB | YANG | YANG | ❌ loose `NodeValue` typing only |
| Read-only enforcement | ✅ MAX-ACCESS | ✅ `config false` | ✅ | ✅ global `readOnly` paths that bind every identity, enforced on the nodes actually touched |
| Config vs. operational state as a schema concept | ✅ | ✅ | ✅ | ⚠️ by policy path patterns only; there is no schema saying which nodes are state |
| Capability negotiation | ❌ | ✅ `hello` | ✅ `Capabilities` | ❌ |
| Interval telemetry | polling | RFC 8640 | ✅ SAMPLE | ✅ `Query`, `interval` mode |
| Event-driven telemetry | ❌ | ✅ | ✅ ON_CHANGE | ✅ `Query`, `onChange` mode (baseline push, then diffed pushes) |
| Cancel one subscription | n/a | ✅ | ✅ | ✅ delete the query's own results node (or an ancestor) |
| Timestamps on pushed data | n/a | ✅ | ✅ | ⚠️ each `Query` push is a subtree rooted at its transfer timestamp (UTC, ns), also kept in session state; it is transfer time, not per-sample time, and `Get` responses carry none |
| Explicit "baseline done" marker | n/a | ✅ | ✅ | ❌ the first `onChange` push is the baseline, but nothing says so |
| Deletions reported to subscribers | n/a | ✅ | ✅ | ❌ `onChange` reports additions and changes only |
| Async unsolicited notifications | ✅ TRAP/INFORM | ✅ | via ON_CHANGE | ❌ everything is triggered by a client's own standing request |
| Reliability | ❌ (UDP) | ✅ (TCP) | ✅ | ✅ `SummaryAck` (fixed-interval retransmit, not adaptive) |
| Long-lived connections | n/a | ✅ | ✅ | ✅ keep-alives set; per-session state bounded |
| Authentication | USM | SSH / TLS | mTLS / tokens | ✅ mutual TLS; the client certificate's CommonName is the identity |
| Per-identity authorization | VACM | NACM | interceptor-level | ✅ per-identity read/write/delete path rules, deny by default; unreadable nodes are absent, not "forbidden"; sessions isolated from each other |
| Revocation, policy reload, audit trail | varies | varies | varies | ❌ no CRL/OCSP, policy loaded once at startup, no audit log |
| Server-side aggregation | ❌ | ❌ | ❌ | ✅ min/max/mean/stdDev/percentile in `Query` |
| Identity of a pushed value | n/a | ✅ | ✅ | ❌ a `Query` leaf carries only the node's own key, so values from many nodes sharing a key (one `ifDescr` per interface, one metric per host) can't be told apart |
| Throughput as a collector | n/a | n/a | n/a | ⚠️ measured in [`goimpl/LOADTEST.md`](goimpl/LOADTEST.md): ~6-10x the CPU of the OpenTelemetry Collector per data point, and not sustaining 70k points/s with a subscriber; part implementation, part protocol (25 points per request) |
| Value types | full SMI | YANG | typed | ⚠️ SNMP-inspired subset; no IpAddress, OID or Opaque; no counter-wrap-aware rates |

## Remaining gaps, in priority order

1. **Async notifications.** The biggest functional hole shared by all three
   reference protocols: nothing is server-initiated independent of a
   client's own standing request.
2. **Query results that identify their source node.** A pushed value says
   `m0042=5` but not which host's `m0042`. Any multi-node query is ambiguous
   until the push carries the path (or mirrors the matched tree's shape).
3. **Per-sample timestamps, timestamps on `Get`, and a baseline marker.** Pushes
   now carry their transfer time; a telemetry consumer still can't tell when a
   value was actually sampled, or which push is the baseline.
4. **Deletion reporting in `onChange`, and staged edits to existing values.**
5. **Operating access control for real:** revocation, policy reload, an audit
   trail, and making authenticated mode the default rather than open mode.
6. **Replace, locking, schema validation, capability negotiation.** Larger
   lifts, lower urgency.
