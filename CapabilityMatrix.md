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
| Config vs. operational state, read-only enforcement | ✅ MAX-ACCESS | ✅ `config false` | ✅ | ❌ any client can `Set` or `Delete` anything |
| Capability negotiation | ❌ | ✅ `hello` | ✅ `Capabilities` | ❌ |
| Interval telemetry | polling | RFC 8640 | ✅ SAMPLE | ✅ `Query`, `interval` mode |
| Event-driven telemetry | ❌ | ✅ | ✅ ON_CHANGE | ✅ `Query`, `onChange` mode (baseline push, then diffed pushes) |
| Cancel one subscription | n/a | ✅ | ✅ | ✅ delete the query's own results node (or an ancestor) |
| Sync marker / per-update timestamps | n/a | ✅ | ✅ | ❌ no timestamps; no explicit "baseline done" marker |
| Deletions reported to subscribers | n/a | ✅ | ✅ | ❌ `onChange` reports additions and changes only |
| Async unsolicited notifications | ✅ TRAP/INFORM | ✅ | via ON_CHANGE | ❌ everything is triggered by a client's own standing request |
| Reliability | ❌ (UDP) | ✅ (TCP) | ✅ | ✅ `SummaryAck` (fixed-interval retransmit, not adaptive) |
| Long-lived connections | n/a | ✅ | ✅ | ✅ keep-alives set; per-session state bounded |
| AAA / per-user authorization | USM + VACM | SSH + NACM | mTLS / tokens | ❌ no real mTLS, no identity |
| Server-side aggregation | ❌ | ❌ | ❌ | ✅ min/max/mean/stdDev/percentile in `Query` |
| Value types | full SMI | YANG | typed | ⚠️ SNMP-inspired subset; no IpAddress, OID or Opaque; no counter-wrap-aware rates |

## Remaining gaps, in priority order

1. **AAA and read-only enforcement, together.** Identity (mTLS) only matters
   once something can say what an identity may touch. Today nothing is
   protected.
2. **Async notifications.** The biggest functional hole shared by all three
   reference protocols: nothing is server-initiated independent of a
   client's own standing request.
3. **Timestamps and a sync marker on pushes.** Cheap to add, and a telemetry
   consumer needs both.
4. **Deletion reporting in `onChange`, and staged edits to existing values.**
5. **Replace, locking, schema validation, capability negotiation.** Larger
   lifts, lower urgency.
