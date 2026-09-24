package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// fixtures.json is generated from node.asn by the reference Python/BER
// implementation (asn1tools), independently of this Go codec -- see the
// generation script referenced in goimpl/README.md. Testing against it
// (rather than just round-tripping within Go) is what actually verifies
// this codec matches what node.asn's AUTOMATIC TAGS numbering produces,
// not just that Marshal/Unmarshal agree with each other.
type fixture struct {
	Type string `json:"type"`
	Hex  string `json:"hex"`
}

func loadFixtures(t *testing.T) map[string]fixture {
	t.Helper()
	data, err := os.ReadFile("testdata_fixtures.json")
	if err != nil {
		t.Fatalf("reading fixtures: %v", err)
	}
	var fixtures map[string]fixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatalf("parsing fixtures: %v", err)
	}
	return fixtures
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// checkFixture marshals `value` and confirms it matches the fixture's hex
// exactly, then unmarshals the fixture's hex via `unmarshal` and confirms
// it produces a value deep-equal to `value`.
func checkFixture[T any](t *testing.T, fixtures map[string]fixture, name string, value []byte, unmarshal func([]byte) (T, error), want T) {
	t.Helper()
	f, ok := fixtures[name]
	if !ok {
		t.Fatalf("missing fixture %q", name)
	}
	wantBytes := mustHex(t, f.Hex)
	if hex.EncodeToString(value) != f.Hex {
		t.Errorf("%s: Marshal mismatch\n  got:  %x\n  want: %x", name, value, wantBytes)
	}
	got, err := unmarshal(wantBytes)
	if err != nil {
		t.Errorf("%s: Unmarshal error: %v", name, err)
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: Unmarshal mismatch\n  got:  %#v\n  want: %#v", name, got, want)
	}
}

func TestNodePointerFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	checkFixture(t, fixtures, "NodePointer_none", MarshalNodePointer(NonePointer()), UnmarshalNodePointer, NonePointer())
	checkFixture(t, fixtures, "NodePointer_absolute", MarshalNodePointer(AbsolutePointer("/users")), UnmarshalNodePointer, AbsolutePointer("/users"))
	checkFixture(t, fixtures, "NodePointer_offset", MarshalNodePointer(OffsetPointer(5)), UnmarshalNodePointer, OffsetPointer(5))
}

func TestNodeValueFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	checkFixture(t, fixtures, "NodeValue_integer32", MarshalNodeValue(Integer32Value(-42)), UnmarshalNodeValue, Integer32Value(-42))
	checkFixture(t, fixtures, "NodeValue_unsigned32", MarshalNodeValue(Unsigned32Value(42)), UnmarshalNodeValue, Unsigned32Value(42))
	checkFixture(t, fixtures, "NodeValue_counter64", MarshalNodeValue(Counter64Value(18000000000000000000)), UnmarshalNodeValue, Counter64Value(18000000000000000000))
	checkFixture(t, fixtures, "NodeValue_octetString", MarshalNodeValue(StringValue("hello")), UnmarshalNodeValue, StringValue("hello"))
	checkFixture(t, fixtures, "NodeValue_real", MarshalNodeValue(RealValue(3.14159)), UnmarshalNodeValue, RealValue(3.14159))
	checkFixture(t, fixtures, "NodeValue_noValue", MarshalNodeValue(NoValue()), UnmarshalNodeValue, NoValue())
}

func TestNodeFixture(t *testing.T) {
	fixtures := loadFixtures(t)
	node := Node{Key: "alice", Value: StringValue("admin"), FirstChild: NonePointer(), NextSibling: OffsetPointer(1)}
	checkFixture(t, fixtures, "Node_alice", MarshalNode(node), UnmarshalNode, node)
}

func TestGetFixture(t *testing.T) {
	fixtures := loadFixtures(t)
	g := &Get{SequenceNumber: 1, Target: AbsolutePointer("/users")}
	checkFixture(t, fixtures, "Get_1", MarshalGet(g), UnmarshalGet, g)
}

func TestSetFixture(t *testing.T) {
	fixtures := loadFixtures(t)
	newValue := StringValue("root")
	newFirstChild := NonePointer()
	s := &Set{
		SequenceNumber: 2,
		Target:         AbsolutePointer("/users/user=alice"),
		NewValue:       &newValue,
		NewFirstChild:  &newFirstChild,
	}
	checkFixture(t, fixtures, "Set_1", MarshalSet(s), UnmarshalSet, s)
}

func TestCreateFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	v := StringValue("hi")
	c1 := &Create{SequenceNumber: 3, Key: "note", Value: &v}
	checkFixture(t, fixtures, "Create_1", MarshalCreate(c1), UnmarshalCreate, c1)

	c2 := &Create{SequenceNumber: 4, Key: "container"}
	checkFixture(t, fixtures, "Create_2", MarshalCreate(c2), UnmarshalCreate, c2)
}

func TestQueryFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	agg := AggregationMethod{Kind: AggMean}
	aggInterval := int64(600)
	q1 := &Query{
		SequenceNumber:      5,
		NodeExpression:      "/config/timeout",
		CollectionMode:      IntervalMode(300),
		AggregationInterval: &aggInterval,
		AggregationMethod:   &agg,
		TransferInterval:    6000,
	}
	checkFixture(t, fixtures, "Query_1", MarshalQuery(q1), UnmarshalQuery, q1)

	q2 := &Query{
		SequenceNumber:   6,
		NodeExpression:   "/config/timeout",
		CollectionMode:   OnceMode(),
		TransferInterval: 0,
	}
	checkFixture(t, fixtures, "Query_once", MarshalQuery(q2), UnmarshalQuery, q2)

	q3 := &Query{
		SequenceNumber:   9,
		NodeExpression:   "/interfaces/ifOperStatus",
		CollectionMode:   OnChangeMode(),
		TransferInterval: 5,
	}
	checkFixture(t, fixtures, "Query_onChange", MarshalQuery(q3), UnmarshalQuery, q3)
}

func TestResponseFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	node := Node{Key: "alice", Value: StringValue("admin"), FirstChild: NonePointer(), NextSibling: OffsetPointer(1)}
	rOK := &Response{SequenceNumber: 7, InReplyTo: 1, Error: false, Nodes: []Node{node}}
	checkFixture(t, fixtures, "Response_ok", MarshalResponse(rOK), UnmarshalResponse, rOK)

	errPtr := AbsolutePointer("/Sessions/Connection-ID\\=abc/Errors/NoSuchNode")
	rErr := &Response{SequenceNumber: 8, InReplyTo: 2, Error: true, ErrorNode: &errPtr, Nodes: nil}
	checkFixture(t, fixtures, "Response_error", MarshalResponse(rErr), UnmarshalResponse, rErr)
}

func TestSummaryAckFixture(t *testing.T) {
	fixtures := loadFixtures(t)
	a := &SummaryAck{Received: []SequenceRange{{First: 0, Last: 5}, {First: 8, Last: 8}}}
	checkFixture(t, fixtures, "SummaryAck_1", MarshalSummaryAck(a), UnmarshalSummaryAck, a)
}

func TestNodeTreeMessageFixtures(t *testing.T) {
	fixtures := loadFixtures(t)

	getMsg := Message{Kind: MsgGet, Get: &Get{SequenceNumber: 1, Target: AbsolutePointer("/users")}}
	checkFixture(t, fixtures, "NodeTreeMessage_get", MarshalMessage(getMsg), UnmarshalMessage, getMsg)

	ackMsg := Message{Kind: MsgSummaryAck, SummaryAck: &SummaryAck{Received: []SequenceRange{{First: 0, Last: 3}}}}
	checkFixture(t, fixtures, "NodeTreeMessage_summaryAck", MarshalMessage(ackMsg), UnmarshalMessage, ackMsg)
}

// TestRoundTripAllKinds is a broader internal-consistency sweep beyond the
// fixtures (which only cover a representative subset): every NodeValue and
// NodePointer kind, and a Node exercising each.
func TestRoundTripAllKinds(t *testing.T) {
	values := []NodeValue{
		Integer32Value(-2147483648),
		Integer32Value(2147483647),
		Unsigned32Value(4294967295),
		Counter32Value(4294967295),
		Counter64Value(18446744073709551615),
		TimeTicksValue(12345),
		{Kind: ValueOctetString, OctetString: nil}, // matches how decode leaves a zero-length OCTET STRING
		OctetStringValue([]byte{0, 1, 2, 255}),
		RealValue(0),
		RealValue(-2.5),
		RealValue(1e300),
		NoValue(),
	}
	for _, v := range values {
		got, err := UnmarshalNodeValue(MarshalNodeValue(v))
		if err != nil {
			t.Fatalf("NodeValue %+v: %v", v, err)
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("NodeValue round-trip mismatch: got %#v want %#v", got, v)
		}
	}

	pointers := []NodePointer{
		AbsolutePointer(""),
		AbsolutePointer("/a/b=c\\=d"),
		OffsetPointer(-1000),
		OffsetPointer(0),
		NonePointer(),
	}
	for _, p := range pointers {
		got, err := UnmarshalNodePointer(MarshalNodePointer(p))
		if err != nil {
			t.Fatalf("NodePointer %+v: %v", p, err)
		}
		if !reflect.DeepEqual(got, p) {
			t.Errorf("NodePointer round-trip mismatch: got %#v want %#v", got, p)
		}
	}
}
