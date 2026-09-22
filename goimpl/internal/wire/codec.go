package wire

import (
	"bytes"
	"fmt"
)

// --- NodePointer (CHOICE, no outer wrapper) --------------------------------

func encodeNodePointer(buf *bytes.Buffer, p NodePointer) {
	switch p.Kind {
	case PointerAbsolute:
		encodeString(buf, classContext, false, 0, p.Absolute)
	case PointerOffset:
		encodeInt64(buf, classContext, false, 1, p.Offset)
	case PointerNone:
		encodeNull(buf, classContext, false, 2)
	default:
		panic(fmt.Sprintf("wire: invalid NodePointerKind %d", p.Kind))
	}
}

func MarshalNodePointer(p NodePointer) []byte {
	var buf bytes.Buffer
	encodeNodePointer(&buf, p)
	return buf.Bytes()
}

func decodeNodePointer(data []byte) (NodePointer, error) {
	t, rest, err := readTLV(data)
	if err != nil {
		return NodePointer{}, err
	}
	if len(rest) != 0 {
		return NodePointer{}, fmt.Errorf("wire: %d trailing byte(s) after NodePointer", len(rest))
	}
	if t.class != classContext {
		return NodePointer{}, fmt.Errorf("wire: NodePointer: expected context class, got %d", t.class)
	}
	switch t.tag {
	case 0:
		return NodePointer{Kind: PointerAbsolute, Absolute: string(t.content)}, nil
	case 1:
		v, err := decodeInt64(t.content)
		if err != nil {
			return NodePointer{}, fmt.Errorf("wire: NodePointer.offset: %w", err)
		}
		return NodePointer{Kind: PointerOffset, Offset: v}, nil
	case 2:
		return NodePointer{Kind: PointerNone}, nil
	default:
		return NodePointer{}, fmt.Errorf("wire: NodePointer: unknown alternative tag %d", t.tag)
	}
}

func UnmarshalNodePointer(data []byte) (NodePointer, error) { return decodeNodePointer(data) }

// --- NodeValue (CHOICE, no outer wrapper) ----------------------------------

const realByteLen = 8

func encodeNodeValue(buf *bytes.Buffer, v NodeValue) {
	switch v.Kind {
	case ValueInteger32:
		encodeInt64(buf, classContext, false, 0, int64(v.Integer32))
	case ValueUnsigned32:
		encodeBigUint(buf, classContext, false, 1, uint64(v.Unsigned32))
	case ValueCounter32:
		encodeBigUint(buf, classContext, false, 2, uint64(v.Counter32))
	case ValueCounter64:
		encodeBigUint(buf, classContext, false, 3, v.Counter64)
	case ValueTimeTicks:
		encodeBigUint(buf, classContext, false, 4, uint64(v.TimeTicks))
	case ValueOctetString:
		encodeBytes(buf, classContext, false, 5, v.OctetString)
	case ValueReal:
		encodeBytes(buf, classContext, false, 6, float64ToBytes(v.Real))
	case ValueNoValue:
		encodeNull(buf, classContext, false, 7)
	default:
		panic(fmt.Sprintf("wire: invalid NodeValueKind %d", v.Kind))
	}
}

func MarshalNodeValue(v NodeValue) []byte {
	var buf bytes.Buffer
	encodeNodeValue(&buf, v)
	return buf.Bytes()
}

func decodeNodeValue(data []byte) (NodeValue, error) {
	t, rest, err := readTLV(data)
	if err != nil {
		return NodeValue{}, err
	}
	if len(rest) != 0 {
		return NodeValue{}, fmt.Errorf("wire: %d trailing byte(s) after NodeValue", len(rest))
	}
	if t.class != classContext {
		return NodeValue{}, fmt.Errorf("wire: NodeValue: expected context class, got %d", t.class)
	}
	switch t.tag {
	case 0:
		v, err := decodeInt64(t.content)
		if err != nil {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.integer32: %w", err)
		}
		if v < -2147483648 || v > 2147483647 {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.integer32: %d out of Integer32 range", v)
		}
		return NodeValue{Kind: ValueInteger32, Integer32: int32(v)}, nil
	case 1:
		v, err := decodeUint64(t.content)
		if err != nil || v > 4294967295 {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.unsigned32: invalid: %v", err)
		}
		return NodeValue{Kind: ValueUnsigned32, Unsigned32: uint32(v)}, nil
	case 2:
		v, err := decodeUint64(t.content)
		if err != nil || v > 4294967295 {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.counter32: invalid: %v", err)
		}
		return NodeValue{Kind: ValueCounter32, Counter32: uint32(v)}, nil
	case 3:
		v, err := decodeUint64(t.content)
		if err != nil {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.counter64: %w", err)
		}
		return NodeValue{Kind: ValueCounter64, Counter64: v}, nil
	case 4:
		v, err := decodeUint64(t.content)
		if err != nil || v > 4294967295 {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.timeTicks: invalid: %v", err)
		}
		return NodeValue{Kind: ValueTimeTicks, TimeTicks: uint32(v)}, nil
	case 5:
		return NodeValue{Kind: ValueOctetString, OctetString: append([]byte(nil), t.content...)}, nil
	case 6:
		if len(t.content) != realByteLen {
			return NodeValue{}, fmt.Errorf("wire: NodeValue.real: expected %d bytes, got %d", realByteLen, len(t.content))
		}
		return NodeValue{Kind: ValueReal, Real: bytesToFloat64(t.content)}, nil
	case 7:
		return NodeValue{Kind: ValueNoValue}, nil
	default:
		return NodeValue{}, fmt.Errorf("wire: NodeValue: unknown alternative tag %d", t.tag)
	}
}

func UnmarshalNodeValue(data []byte) (NodeValue, error) { return decodeNodeValue(data) }

// --- Node (SEQUENCE) --------------------------------------------------------

func encodeNodeFields(buf *bytes.Buffer, n Node) {
	encodeString(buf, classContext, false, 0, n.Key)

	var vbuf bytes.Buffer
	encodeNodeValue(&vbuf, n.Value)
	writeTagLen(buf, classContext, true, 1, vbuf.Len())
	buf.Write(vbuf.Bytes())

	var fbuf bytes.Buffer
	encodeNodePointer(&fbuf, n.FirstChild)
	writeTagLen(buf, classContext, true, 2, fbuf.Len())
	buf.Write(fbuf.Bytes())

	var sbuf bytes.Buffer
	encodeNodePointer(&sbuf, n.NextSibling)
	writeTagLen(buf, classContext, true, 3, sbuf.Len())
	buf.Write(sbuf.Bytes())
}

func MarshalNode(n Node) []byte {
	var fields bytes.Buffer
	encodeNodeFields(&fields, n)
	var buf bytes.Buffer
	writeTagLen(&buf, classUniversal, true, tagSequence, fields.Len())
	buf.Write(fields.Bytes())
	return buf.Bytes()
}

func decodeNodeFields(content []byte) (Node, error) {
	var n Node
	rest := content

	t, r, err := readTLV(rest)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.key: %w", err)
	}
	n.Key = string(t.content)
	rest = r

	t, r, err = readTLV(rest)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.value: %w", err)
	}
	n.Value, err = decodeNodeValue(t.content)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.value: %w", err)
	}
	rest = r

	t, r, err = readTLV(rest)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.firstChild: %w", err)
	}
	n.FirstChild, err = decodeNodePointer(t.content)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.firstChild: %w", err)
	}
	rest = r

	t, r, err = readTLV(rest)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.nextSibling: %w", err)
	}
	n.NextSibling, err = decodeNodePointer(t.content)
	if err != nil {
		return Node{}, fmt.Errorf("wire: Node.nextSibling: %w", err)
	}
	rest = r

	if len(rest) != 0 {
		return Node{}, fmt.Errorf("wire: %d trailing byte(s) after Node", len(rest))
	}
	return n, nil
}

func UnmarshalNode(data []byte) (Node, error) {
	t, rest, err := readTLV(data)
	if err != nil {
		return Node{}, err
	}
	if len(rest) != 0 {
		return Node{}, fmt.Errorf("wire: %d trailing byte(s) after Node", len(rest))
	}
	if t.class != classUniversal || t.tag != tagSequence {
		return Node{}, fmt.Errorf("wire: Node: expected universal SEQUENCE, got class=%d tag=%d", t.class, t.tag)
	}
	return decodeNodeFields(t.content)
}

// --- AggregationMethod (CHOICE, no outer wrapper) --------------------------

func encodeAggregationMethod(buf *bytes.Buffer, m AggregationMethod) {
	switch m.Kind {
	case AggMin:
		encodeNull(buf, classContext, false, 0)
	case AggMax:
		encodeNull(buf, classContext, false, 1)
	case AggMean:
		encodeNull(buf, classContext, false, 2)
	case AggStdDev:
		encodeNull(buf, classContext, false, 3)
	case AggPercentile:
		encodeInt64(buf, classContext, false, 4, m.Percentile)
	default:
		panic(fmt.Sprintf("wire: invalid AggregationKind %d", m.Kind))
	}
}

func decodeAggregationMethod(data []byte) (AggregationMethod, error) {
	t, rest, err := readTLV(data)
	if err != nil {
		return AggregationMethod{}, err
	}
	if len(rest) != 0 {
		return AggregationMethod{}, fmt.Errorf("wire: %d trailing byte(s) after AggregationMethod", len(rest))
	}
	if t.class != classContext {
		return AggregationMethod{}, fmt.Errorf("wire: AggregationMethod: expected context class, got %d", t.class)
	}
	switch t.tag {
	case 0:
		return AggregationMethod{Kind: AggMin}, nil
	case 1:
		return AggregationMethod{Kind: AggMax}, nil
	case 2:
		return AggregationMethod{Kind: AggMean}, nil
	case 3:
		return AggregationMethod{Kind: AggStdDev}, nil
	case 4:
		v, err := decodeInt64(t.content)
		if err != nil || v < 0 || v > 100 {
			return AggregationMethod{}, fmt.Errorf("wire: AggregationMethod.percentile: invalid: %v", err)
		}
		return AggregationMethod{Kind: AggPercentile, Percentile: v}, nil
	default:
		return AggregationMethod{}, fmt.Errorf("wire: AggregationMethod: unknown alternative tag %d", t.tag)
	}
}

// --- Get / Set / Create / Query / Response / SummaryAck --------------------
//
// Each of these SEQUENCE types has two encoders: an "outer" one (universal
// SEQUENCE tag, for standalone use) and an "into" one used only by the
// NodeTreeMessage envelope, which IMPLICIT-tags the same field content with
// a context tag instead of the universal SEQUENCE tag.

func encodeGetFields(buf *bytes.Buffer, g *Get) {
	encodeInt64(buf, classContext, false, 0, g.SequenceNumber)
	var tbuf bytes.Buffer
	encodeNodePointer(&tbuf, g.Target)
	writeTagLen(buf, classContext, true, 1, tbuf.Len())
	buf.Write(tbuf.Bytes())
}

func MarshalGet(g *Get) []byte { return wrapSequence(encodeGetFields, g) }

func decodeGetFields(content []byte) (*Get, error) {
	g := &Get{}
	t, rest, err := readTLV(content)
	if err != nil {
		return nil, fmt.Errorf("wire: Get.sequenceNumber: %w", err)
	}
	if g.SequenceNumber, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Get.sequenceNumber: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Get.target: %w", err)
	}
	if g.Target, err = decodeNodePointer(t.content); err != nil {
		return nil, fmt.Errorf("wire: Get.target: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("wire: %d trailing byte(s) after Get", len(rest))
	}
	return g, nil
}

func UnmarshalGet(data []byte) (*Get, error) {
	content, err := unwrapSequence(data, "Get")
	if err != nil {
		return nil, err
	}
	return decodeGetFields(content)
}

func encodeSetFields(buf *bytes.Buffer, s *Set) {
	encodeInt64(buf, classContext, false, 0, s.SequenceNumber)
	writeExplicitPointer(buf, 1, s.Target)
	if s.NewValue != nil {
		writeExplicitValue(buf, 2, *s.NewValue)
	}
	if s.NewFirstChild != nil {
		writeExplicitPointer(buf, 3, *s.NewFirstChild)
	}
	if s.NewNextSibling != nil {
		writeExplicitPointer(buf, 4, *s.NewNextSibling)
	}
}

func MarshalSet(s *Set) []byte { return wrapSequence(encodeSetFields, s) }

func decodeSetFields(content []byte) (*Set, error) {
	s := &Set{}
	t, rest, err := readTLV(content)
	if err != nil {
		return nil, fmt.Errorf("wire: Set.sequenceNumber: %w", err)
	}
	if s.SequenceNumber, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Set.sequenceNumber: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Set.target: %w", err)
	}
	if s.Target, err = decodeNodePointer(t.content); err != nil {
		return nil, fmt.Errorf("wire: Set.target: %w", err)
	}
	for len(rest) > 0 {
		t, rest, err = readTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("wire: Set: %w", err)
		}
		switch t.tag {
		case 2:
			v, err := decodeNodeValue(t.content)
			if err != nil {
				return nil, fmt.Errorf("wire: Set.newValue: %w", err)
			}
			s.NewValue = &v
		case 3:
			p, err := decodeNodePointer(t.content)
			if err != nil {
				return nil, fmt.Errorf("wire: Set.newFirstChild: %w", err)
			}
			s.NewFirstChild = &p
		case 4:
			p, err := decodeNodePointer(t.content)
			if err != nil {
				return nil, fmt.Errorf("wire: Set.newNextSibling: %w", err)
			}
			s.NewNextSibling = &p
		default:
			return nil, fmt.Errorf("wire: Set: unexpected field tag %d", t.tag)
		}
	}
	return s, nil
}

func UnmarshalSet(data []byte) (*Set, error) {
	content, err := unwrapSequence(data, "Set")
	if err != nil {
		return nil, err
	}
	return decodeSetFields(content)
}

func encodeCreateFields(buf *bytes.Buffer, c *Create) {
	encodeInt64(buf, classContext, false, 0, c.SequenceNumber)
	encodeString(buf, classContext, false, 1, c.Key)
	if c.Value != nil {
		writeExplicitValue(buf, 2, *c.Value)
	}
}

func MarshalCreate(c *Create) []byte { return wrapSequence(encodeCreateFields, c) }

func decodeCreateFields(content []byte) (*Create, error) {
	c := &Create{}
	t, rest, err := readTLV(content)
	if err != nil {
		return nil, fmt.Errorf("wire: Create.sequenceNumber: %w", err)
	}
	if c.SequenceNumber, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Create.sequenceNumber: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Create.key: %w", err)
	}
	c.Key = string(t.content)
	if len(rest) > 0 {
		t, rest, err = readTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("wire: Create.value: %w", err)
		}
		if t.tag != 2 {
			return nil, fmt.Errorf("wire: Create: unexpected field tag %d", t.tag)
		}
		v, err := decodeNodeValue(t.content)
		if err != nil {
			return nil, fmt.Errorf("wire: Create.value: %w", err)
		}
		c.Value = &v
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("wire: %d trailing byte(s) after Create", len(rest))
	}
	return c, nil
}

func UnmarshalCreate(data []byte) (*Create, error) {
	content, err := unwrapSequence(data, "Create")
	if err != nil {
		return nil, err
	}
	return decodeCreateFields(content)
}

func encodeQueryFields(buf *bytes.Buffer, q *Query) {
	encodeInt64(buf, classContext, false, 0, q.SequenceNumber)
	encodeString(buf, classContext, false, 1, q.NodeExpression)
	encodeInt64(buf, classContext, false, 2, q.CollectionInterval)
	if q.AggregationInterval != nil {
		encodeInt64(buf, classContext, false, 3, *q.AggregationInterval)
	}
	if q.AggregationMethod != nil {
		var mbuf bytes.Buffer
		encodeAggregationMethod(&mbuf, *q.AggregationMethod)
		writeTagLen(buf, classContext, true, 4, mbuf.Len())
		buf.Write(mbuf.Bytes())
	}
	encodeInt64(buf, classContext, false, 5, q.TransferInterval)
}

func MarshalQuery(q *Query) []byte { return wrapSequence(encodeQueryFields, q) }

func decodeQueryFields(content []byte) (*Query, error) {
	q := &Query{}
	rest := content
	var t tlv
	var err error

	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Query.sequenceNumber: %w", err)
	}
	if q.SequenceNumber, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Query.sequenceNumber: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Query.nodeExpression: %w", err)
	}
	q.NodeExpression = string(t.content)
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Query.collectionInterval: %w", err)
	}
	if q.CollectionInterval, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Query.collectionInterval: %w", err)
	}

	for len(rest) > 0 {
		t, rest, err = readTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("wire: Query: %w", err)
		}
		switch t.tag {
		case 3:
			v, err := decodeInt64(t.content)
			if err != nil {
				return nil, fmt.Errorf("wire: Query.aggregationInterval: %w", err)
			}
			q.AggregationInterval = &v
		case 4:
			m, err := decodeAggregationMethod(t.content)
			if err != nil {
				return nil, fmt.Errorf("wire: Query.aggregationMethod: %w", err)
			}
			q.AggregationMethod = &m
		case 5:
			v, err := decodeInt64(t.content)
			if err != nil {
				return nil, fmt.Errorf("wire: Query.transferInterval: %w", err)
			}
			q.TransferInterval = v
		default:
			return nil, fmt.Errorf("wire: Query: unexpected field tag %d", t.tag)
		}
	}
	return q, nil
}

func UnmarshalQuery(data []byte) (*Query, error) {
	content, err := unwrapSequence(data, "Query")
	if err != nil {
		return nil, err
	}
	return decodeQueryFields(content)
}

func encodeResponseFields(buf *bytes.Buffer, r *Response) {
	encodeInt64(buf, classContext, false, 0, r.SequenceNumber)
	encodeInt64(buf, classContext, false, 1, r.InReplyTo)
	encodeBool(buf, classContext, false, 2, r.Error)
	if r.ErrorNode != nil {
		writeExplicitPointer(buf, 3, *r.ErrorNode)
	}
	var nbuf bytes.Buffer
	for _, n := range r.Nodes {
		encodeNodeFieldsWrapped(&nbuf, n)
	}
	writeTagLen(buf, classContext, true, 4, nbuf.Len())
	buf.Write(nbuf.Bytes())
}

// encodeNodeFieldsWrapped writes one Node as it appears inside a SEQUENCE
// OF Node: a normal universal-SEQUENCE-tagged Node, same as MarshalNode.
func encodeNodeFieldsWrapped(buf *bytes.Buffer, n Node) {
	var fields bytes.Buffer
	encodeNodeFields(&fields, n)
	writeTagLen(buf, classUniversal, true, tagSequence, fields.Len())
	buf.Write(fields.Bytes())
}

func MarshalResponse(r *Response) []byte { return wrapSequence(encodeResponseFields, r) }

func decodeResponseFields(content []byte) (*Response, error) {
	r := &Response{}
	rest := content
	var t tlv
	var err error

	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Response.sequenceNumber: %w", err)
	}
	if r.SequenceNumber, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Response.sequenceNumber: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Response.inReplyTo: %w", err)
	}
	if r.InReplyTo, err = decodeInt64(t.content); err != nil {
		return nil, fmt.Errorf("wire: Response.inReplyTo: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Response.error: %w", err)
	}
	if r.Error, err = decodeBool(t.content); err != nil {
		return nil, fmt.Errorf("wire: Response.error: %w", err)
	}

	t, rest, err = readTLV(rest)
	if err != nil {
		return nil, fmt.Errorf("wire: Response.nodes: %w", err)
	}
	if t.tag == 3 {
		p, err := decodeNodePointer(t.content)
		if err != nil {
			return nil, fmt.Errorf("wire: Response.errorNode: %w", err)
		}
		r.ErrorNode = &p
		t, rest, err = readTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("wire: Response.nodes: %w", err)
		}
	}
	if t.tag != 4 {
		return nil, fmt.Errorf("wire: Response: expected nodes (tag 4), got tag %d", t.tag)
	}
	nodesContent := t.content
	for len(nodesContent) > 0 {
		var nt tlv
		nt, nodesContent, err = readTLV(nodesContent)
		if err != nil {
			return nil, fmt.Errorf("wire: Response.nodes: %w", err)
		}
		if nt.class != classUniversal || nt.tag != tagSequence {
			return nil, fmt.Errorf("wire: Response.nodes: element is not a SEQUENCE (class=%d tag=%d)", nt.class, nt.tag)
		}
		n, err := decodeNodeFields(nt.content)
		if err != nil {
			return nil, fmt.Errorf("wire: Response.nodes: %w", err)
		}
		r.Nodes = append(r.Nodes, n)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("wire: %d trailing byte(s) after Response", len(rest))
	}
	return r, nil
}

func UnmarshalResponse(data []byte) (*Response, error) {
	content, err := unwrapSequence(data, "Response")
	if err != nil {
		return nil, err
	}
	return decodeResponseFields(content)
}

func encodeSequenceRangeFields(buf *bytes.Buffer, r SequenceRange) {
	encodeInt64(buf, classContext, false, 0, r.First)
	encodeInt64(buf, classContext, false, 1, r.Last)
}

func encodeSequenceRangeWrapped(buf *bytes.Buffer, r SequenceRange) {
	var fields bytes.Buffer
	encodeSequenceRangeFields(&fields, r)
	writeTagLen(buf, classUniversal, true, tagSequence, fields.Len())
	buf.Write(fields.Bytes())
}

func decodeSequenceRangeFields(content []byte) (SequenceRange, error) {
	var sr SequenceRange
	t, rest, err := readTLV(content)
	if err != nil {
		return SequenceRange{}, fmt.Errorf("wire: SequenceRange.first: %w", err)
	}
	if sr.First, err = decodeInt64(t.content); err != nil {
		return SequenceRange{}, fmt.Errorf("wire: SequenceRange.first: %w", err)
	}
	t, rest, err = readTLV(rest)
	if err != nil {
		return SequenceRange{}, fmt.Errorf("wire: SequenceRange.last: %w", err)
	}
	if sr.Last, err = decodeInt64(t.content); err != nil {
		return SequenceRange{}, fmt.Errorf("wire: SequenceRange.last: %w", err)
	}
	if len(rest) != 0 {
		return SequenceRange{}, fmt.Errorf("wire: %d trailing byte(s) after SequenceRange", len(rest))
	}
	return sr, nil
}

func encodeSummaryAckFields(buf *bytes.Buffer, a *SummaryAck) {
	var rbuf bytes.Buffer
	for _, r := range a.Received {
		encodeSequenceRangeWrapped(&rbuf, r)
	}
	writeTagLen(buf, classContext, true, 0, rbuf.Len())
	buf.Write(rbuf.Bytes())
}

func MarshalSummaryAck(a *SummaryAck) []byte { return wrapSequence(encodeSummaryAckFields, a) }

func decodeSummaryAckFields(content []byte) (*SummaryAck, error) {
	a := &SummaryAck{}
	t, rest, err := readTLV(content)
	if err != nil {
		return nil, fmt.Errorf("wire: SummaryAck.received: %w", err)
	}
	if t.tag != 0 {
		return nil, fmt.Errorf("wire: SummaryAck: expected tag 0, got %d", t.tag)
	}
	rangesContent := t.content
	for len(rangesContent) > 0 {
		var rt tlv
		rt, rangesContent, err = readTLV(rangesContent)
		if err != nil {
			return nil, fmt.Errorf("wire: SummaryAck.received: %w", err)
		}
		sr, err := decodeSequenceRangeFields(rt.content)
		if err != nil {
			return nil, fmt.Errorf("wire: SummaryAck.received: %w", err)
		}
		a.Received = append(a.Received, sr)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("wire: %d trailing byte(s) after SummaryAck", len(rest))
	}
	return a, nil
}

func UnmarshalSummaryAck(data []byte) (*SummaryAck, error) {
	content, err := unwrapSequence(data, "SummaryAck")
	if err != nil {
		return nil, err
	}
	return decodeSummaryAckFields(content)
}

// --- NodeTreeMessage (CHOICE, no outer wrapper; arms are IMPLICIT) ---------

func MarshalMessage(m Message) []byte {
	var buf bytes.Buffer
	switch m.Kind {
	case MsgGet:
		writeImplicitInto(&buf, 0, encodeGetFields, m.Get)
	case MsgSet:
		writeImplicitInto(&buf, 1, encodeSetFields, m.Set)
	case MsgCreate:
		writeImplicitInto(&buf, 2, encodeCreateFields, m.Create)
	case MsgQuery:
		writeImplicitInto(&buf, 3, encodeQueryFields, m.Query)
	case MsgResponse:
		writeImplicitInto(&buf, 4, encodeResponseFields, m.Response)
	case MsgSummaryAck:
		writeImplicitInto(&buf, 5, encodeSummaryAckFields, m.SummaryAck)
	default:
		panic(fmt.Sprintf("wire: invalid MessageKind %d", m.Kind))
	}
	return buf.Bytes()
}

func UnmarshalMessage(data []byte) (Message, error) {
	t, rest, err := readTLV(data)
	if err != nil {
		return Message{}, err
	}
	if len(rest) != 0 {
		return Message{}, fmt.Errorf("wire: %d trailing byte(s) after NodeTreeMessage", len(rest))
	}
	if t.class != classContext {
		return Message{}, fmt.Errorf("wire: NodeTreeMessage: expected context class, got %d", t.class)
	}
	switch t.tag {
	case 0:
		g, err := decodeGetFields(t.content)
		if err != nil {
			return Message{}, err
		}
		return Message{Kind: MsgGet, Get: g}, nil
	case 1:
		s, err := decodeSetFields(t.content)
		if err != nil {
			return Message{}, err
		}
		return Message{Kind: MsgSet, Set: s}, nil
	case 2:
		c, err := decodeCreateFields(t.content)
		if err != nil {
			return Message{}, err
		}
		return Message{Kind: MsgCreate, Create: c}, nil
	case 3:
		q, err := decodeQueryFields(t.content)
		if err != nil {
			return Message{}, err
		}
		return Message{Kind: MsgQuery, Query: q}, nil
	case 4:
		r, err := decodeResponseFields(t.content)
		if err != nil {
			return Message{}, err
		}
		return Message{Kind: MsgResponse, Response: r}, nil
	case 5:
		a, err := decodeSummaryAckFields(t.content)
		if err != nil {
			return Message{}, err
		}
		return Message{Kind: MsgSummaryAck, SummaryAck: a}, nil
	default:
		return Message{}, fmt.Errorf("wire: NodeTreeMessage: unknown alternative tag %d", t.tag)
	}
}

// --- shared helpers ---------------------------------------------------------

// wrapSequence runs `encode` to get a type's field bytes, then wraps them in
// a universal SEQUENCE tag for standalone encoding.
func wrapSequence[T any](encode func(*bytes.Buffer, T), v T) []byte {
	var fields bytes.Buffer
	encode(&fields, v)
	var buf bytes.Buffer
	writeTagLen(&buf, classUniversal, true, tagSequence, fields.Len())
	buf.Write(fields.Bytes())
	return buf.Bytes()
}

// writeImplicitInto runs `encode` to get a type's field bytes, then wraps
// them in an IMPLICIT context tag (constructed, since every message type is
// a SEQUENCE) for use as a NodeTreeMessage arm.
func writeImplicitInto[T any](buf *bytes.Buffer, tag int, encode func(*bytes.Buffer, T), v T) {
	var fields bytes.Buffer
	encode(&fields, v)
	writeTagLen(buf, classContext, true, tag, fields.Len())
	buf.Write(fields.Bytes())
}

func unwrapSequence(data []byte, typeName string) ([]byte, error) {
	t, rest, err := readTLV(data)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("wire: %d trailing byte(s) after %s", len(rest), typeName)
	}
	if t.class != classUniversal || t.tag != tagSequence {
		return nil, fmt.Errorf("wire: %s: expected universal SEQUENCE, got class=%d tag=%d", typeName, t.class, t.tag)
	}
	return t.content, nil
}

func writeExplicitPointer(buf *bytes.Buffer, tag int, p NodePointer) {
	var inner bytes.Buffer
	encodeNodePointer(&inner, p)
	writeTagLen(buf, classContext, true, tag, inner.Len())
	buf.Write(inner.Bytes())
}

func writeExplicitValue(buf *bytes.Buffer, tag int, v NodeValue) {
	var inner bytes.Buffer
	encodeNodeValue(&inner, v)
	writeTagLen(buf, classContext, true, tag, inner.Len())
	buf.Write(inner.Bytes())
}
