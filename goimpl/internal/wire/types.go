package wire

import "bytes"

// These Go types mirror node.asn exactly. A CHOICE becomes a Go struct with
// a Kind discriminator plus one field per alternative (only the field named
// by Kind is meaningful) -- Go has no native discriminated union, and this
// keeps the mapping to the ASN.1 CHOICE obvious at each call site, at the
// cost of the caller needing to check Kind before reading a field.

type NodePointerKind int

const (
	PointerAbsolute NodePointerKind = iota
	PointerOffset
	PointerNone
)

type NodePointer struct {
	Kind     NodePointerKind
	Absolute string // Kind == PointerAbsolute
	Offset   int64  // Kind == PointerOffset
}

func AbsolutePointer(expr string) NodePointer {
	return NodePointer{Kind: PointerAbsolute, Absolute: expr}
}
func OffsetPointer(delta int64) NodePointer { return NodePointer{Kind: PointerOffset, Offset: delta} }
func NonePointer() NodePointer              { return NodePointer{Kind: PointerNone} }

type NodeValueKind int

const (
	ValueInteger32 NodeValueKind = iota
	ValueUnsigned32
	ValueCounter32
	ValueCounter64
	ValueTimeTicks
	ValueOctetString
	ValueReal
	ValueNoValue
)

// IsNumeric reports whether this value kind participates in Query
// aggregation (min/max/mean/stdDev/percentile) -- everything except
// octetString and noValue, per node.asn.
func (k NodeValueKind) IsNumeric() bool {
	return k != ValueOctetString && k != ValueNoValue
}

type NodeValue struct {
	Kind        NodeValueKind
	Integer32   int32   // Kind == ValueInteger32
	Unsigned32  uint32  // Kind == ValueUnsigned32
	Counter32   uint32  // Kind == ValueCounter32
	Counter64   uint64  // Kind == ValueCounter64
	TimeTicks   uint32  // Kind == ValueTimeTicks
	OctetString []byte  // Kind == ValueOctetString
	Real        float64 // Kind == ValueReal
}

// AsFloat64 returns v's numeric value for aggregation purposes. Panics if
// !v.Kind.IsNumeric() -- callers must check first (aggregation code does).
func (v NodeValue) AsFloat64() float64 {
	switch v.Kind {
	case ValueInteger32:
		return float64(v.Integer32)
	case ValueUnsigned32:
		return float64(v.Unsigned32)
	case ValueCounter32:
		return float64(v.Counter32)
	case ValueCounter64:
		return float64(v.Counter64)
	case ValueTimeTicks:
		return float64(v.TimeTicks)
	case ValueReal:
		return v.Real
	default:
		panic("wire: AsFloat64 called on a non-numeric NodeValue")
	}
}

// Equal reports whether v and o carry the same Kind and the same
// represented value. Used by Query's onChange collection mode to decide
// whether a freshly sampled value is actually new versus a repeat of what
// was already reported for that key.
func (v NodeValue) Equal(o NodeValue) bool {
	if v.Kind != o.Kind {
		return false
	}
	switch v.Kind {
	case ValueInteger32:
		return v.Integer32 == o.Integer32
	case ValueUnsigned32:
		return v.Unsigned32 == o.Unsigned32
	case ValueCounter32:
		return v.Counter32 == o.Counter32
	case ValueCounter64:
		return v.Counter64 == o.Counter64
	case ValueTimeTicks:
		return v.TimeTicks == o.TimeTicks
	case ValueOctetString:
		return bytes.Equal(v.OctetString, o.OctetString)
	case ValueReal:
		return v.Real == o.Real
	case ValueNoValue:
		return true
	default:
		return false
	}
}

func Integer32Value(v int32) NodeValue   { return NodeValue{Kind: ValueInteger32, Integer32: v} }
func Unsigned32Value(v uint32) NodeValue { return NodeValue{Kind: ValueUnsigned32, Unsigned32: v} }
func Counter32Value(v uint32) NodeValue  { return NodeValue{Kind: ValueCounter32, Counter32: v} }
func Counter64Value(v uint64) NodeValue  { return NodeValue{Kind: ValueCounter64, Counter64: v} }
func TimeTicksValue(v uint32) NodeValue  { return NodeValue{Kind: ValueTimeTicks, TimeTicks: v} }
func OctetStringValue(v []byte) NodeValue {
	return NodeValue{Kind: ValueOctetString, OctetString: v}
}
func StringValue(s string) NodeValue { return OctetStringValue([]byte(s)) }
func RealValue(v float64) NodeValue  { return NodeValue{Kind: ValueReal, Real: v} }
func NoValue() NodeValue             { return NodeValue{Kind: ValueNoValue} }

type Node struct {
	Key         string
	Value       NodeValue
	FirstChild  NodePointer
	NextSibling NodePointer
}

type Get struct {
	SequenceNumber int64
	Target         NodePointer
}

// SetEdit is one target-expression + field-update within a Set request.
// Target is a match expression (the same regex-based grammar as an
// absolute NodePointer, not a NodePointer itself) that may match zero or
// more nodes; see node.asn's SetEdit docs for exactly how each field
// behaves against that match set.
type SetEdit struct {
	Target         string
	NewValue       *NodeValue   // nil = omitted (OPTIONAL, "leave unchanged")
	NewFirstChild  *NodePointer // nil = omitted; a present NonePointer() explicitly clears it
	NewNextSibling *NodePointer
	NewParent      *string // nil = omitted; reparents Target under this expression's resolved node (see node.asn's SetEdit docs)
}

type Set struct {
	SequenceNumber int64
	Edits          []SetEdit
}

type Delete struct {
	SequenceNumber int64
	Targets        []string
}

type Create struct {
	SequenceNumber int64
	Key            string
	Value          *NodeValue // nil = omitted -> server creates a NoValue() container node
	Parent         *string    // nil = omitted -> directly under this session's own NewNodes
}

type AggregationKind int

const (
	AggMin AggregationKind = iota
	AggMax
	AggMean
	AggStdDev
	AggPercentile
)

type AggregationMethod struct {
	Kind       AggregationKind
	Percentile int64 // Kind == AggPercentile, 0..100
}

type CollectionModeKind int

const (
	CollectOnce CollectionModeKind = iota
	CollectInterval
	CollectOnChange
)

type CollectionMode struct {
	Kind     CollectionModeKind
	Interval int64 // seconds; Kind == CollectInterval, must be > 0
}

func OnceMode() CollectionMode { return CollectionMode{Kind: CollectOnce} }
func IntervalMode(seconds int64) CollectionMode {
	return CollectionMode{Kind: CollectInterval, Interval: seconds}
}
func OnChangeMode() CollectionMode { return CollectionMode{Kind: CollectOnChange} }

type Query struct {
	SequenceNumber      int64
	NodeExpression      string
	CollectionMode      CollectionMode
	AggregationInterval *int64
	AggregationMethod   *AggregationMethod
	TransferInterval    int64 // seconds
}

type Response struct {
	SequenceNumber int64
	InReplyTo      int64
	Error          bool
	ErrorNode      *NodePointer
	Nodes          []Node
}

type SequenceRange struct {
	First int64
	Last  int64 // inclusive
}

type SummaryAck struct {
	Received []SequenceRange
}

type MessageKind int

const (
	MsgGet MessageKind = iota
	MsgSet
	MsgCreate
	MsgQuery
	MsgResponse
	MsgSummaryAck
	MsgDelete
)

// Message is the outer envelope actually carried in each QUIC DATAGRAM
// frame (NodeTreeMessage in node.asn).
type Message struct {
	Kind       MessageKind
	Get        *Get
	Set        *Set
	Create     *Create
	Query      *Query
	Response   *Response
	SummaryAck *SummaryAck
	Delete     *Delete
}
