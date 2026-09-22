// Package wire implements a hand-written BER codec for the message types
// defined in node.asn (the repo root's ASN.1 schema), matching exactly what
// that module's AUTOMATIC TAGS numbering produces -- verified against real
// asn1tools-encoded fixtures in codec_test.go.
//
// This is deliberately not built on encoding/asn1's struct-tag system: this
// schema mixes IMPLICIT-tagged plain fields, EXPLICIT-tagged CHOICE fields
// (a CHOICE has no tag of its own, so AUTOMATIC TAGGING wraps it), several
// CHOICE types needing manual dispatch (Go has no discriminated unions), and
// one deliberate deviation from the schema's plain types (NodeValue's `real`
// arm is 8 raw IEEE-754 bytes, not ASN.1 REAL -- see node.asn). Handling all
// of that through struct tags fought the API more than it helped; a direct,
// well-tested TLV codec was more reliable.
package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// float64ToBytes/bytesToFloat64 implement NodeValue's `real` convention: an
// IEEE 754 binary64, big-endian, packed into an 8-byte OCTET STRING (see
// node.asn for why this isn't ASN.1's own REAL type).
func float64ToBytes(f float64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, math.Float64bits(f))
	return b
}

func bytesToFloat64(b []byte) float64 {
	return math.Float64frombits(binary.BigEndian.Uint64(b))
}

// BER/DER tag classes.
const (
	classUniversal   = 0
	classApplication = 1
	classContext     = 2
	classPrivate     = 3
)

// Universal tag numbers used for top-level SEQUENCE encodings.
const (
	tagBoolean    = 1
	tagInteger    = 2
	tagNull       = 5
	tagOctetStr   = 4
	tagUTF8String = 12
	tagSequence   = 16
)

// tlv is one decoded tag-length-value header plus its content bytes.
type tlv struct {
	class       int
	constructed bool
	tag         int
	content     []byte
}

// writeTagLen appends a BER tag-and-length header for `length` bytes of
// content that will follow.
func writeTagLen(buf *bytes.Buffer, class int, constructed bool, tag int, length int) {
	b := byte(class<<6) | byte(tag)
	if constructed {
		b |= 0x20
	}
	if tag >= 31 {
		// Not needed by this schema (every tag here is small), but fail
		// loudly rather than silently emit a wrong encoding if it ever is.
		panic(fmt.Sprintf("wire: high tag number form not implemented (tag=%d)", tag))
	}
	buf.WriteByte(b)
	writeLength(buf, length)
}

func writeLength(buf *bytes.Buffer, length int) {
	if length < 0x80 {
		buf.WriteByte(byte(length))
		return
	}
	var lb []byte
	n := length
	for n > 0 {
		lb = append([]byte{byte(n & 0xff)}, lb...)
		n >>= 8
	}
	buf.WriteByte(0x80 | byte(len(lb)))
	buf.Write(lb)
}

// readTLV parses one TLV structure from the front of data, returning it and
// the remaining bytes after it.
func readTLV(data []byte) (tlv, []byte, error) {
	if len(data) < 2 {
		return tlv{}, nil, fmt.Errorf("wire: truncated tag/length (%d byte(s) left)", len(data))
	}
	first := data[0]
	class := int(first >> 6)
	constructed := first&0x20 != 0
	tag := int(first & 0x1f)
	if tag == 0x1f {
		return tlv{}, nil, fmt.Errorf("wire: high tag number form not supported")
	}
	rest := data[1:]

	lengthByte := rest[0]
	rest = rest[1:]
	var length int
	if lengthByte < 0x80 {
		length = int(lengthByte)
	} else {
		numBytes := int(lengthByte & 0x7f)
		if numBytes == 0 {
			return tlv{}, nil, fmt.Errorf("wire: indefinite length not supported")
		}
		if len(rest) < numBytes {
			return tlv{}, nil, fmt.Errorf("wire: truncated length octets")
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(rest[i])
		}
		rest = rest[numBytes:]
	}
	if len(rest) < length {
		return tlv{}, nil, fmt.Errorf("wire: truncated content (want %d, have %d)", length, len(rest))
	}
	return tlv{class: class, constructed: constructed, tag: tag, content: rest[:length]}, rest[length:], nil
}

// --- INTEGER (minimal two's complement, matching BER/DER) -----------------

func encodeInt64(buf *bytes.Buffer, class int, constructed bool, tag int, v int64) {
	content := minimalTwosComplement(big.NewInt(v))
	writeTagLen(buf, class, constructed, tag, len(content))
	buf.Write(content)
}

func decodeInt64(content []byte) (int64, error) {
	bi, err := decodeBigInt(content)
	if err != nil {
		return 0, err
	}
	if !bi.IsInt64() {
		return 0, fmt.Errorf("wire: INTEGER %s does not fit in int64", bi.String())
	}
	return bi.Int64(), nil
}

func encodeBigUint(buf *bytes.Buffer, class int, constructed bool, tag int, v uint64) {
	content := minimalTwosComplement(new(big.Int).SetUint64(v))
	writeTagLen(buf, class, constructed, tag, len(content))
	buf.Write(content)
}

func decodeUint64(content []byte) (uint64, error) {
	bi, err := decodeBigInt(content)
	if err != nil {
		return 0, err
	}
	if bi.Sign() < 0 || !bi.IsUint64() {
		return 0, fmt.Errorf("wire: INTEGER %s does not fit in uint64", bi.String())
	}
	return bi.Uint64(), nil
}

func minimalTwosComplement(v *big.Int) []byte {
	if v.Sign() == 0 {
		return []byte{0}
	}
	if v.Sign() > 0 {
		b := v.Bytes()
		if b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return b
	}
	// Negative: two's complement over the smallest sufficient byte length.
	bitLen := v.BitLen() // magnitude bit length
	nBytes := bitLen/8 + 1
	mod := new(big.Int).Lsh(big.NewInt(1), uint(nBytes*8))
	tc := new(big.Int).Add(mod, v) // mod + v, v is negative
	b := tc.Bytes()
	for len(b) < nBytes {
		b = append([]byte{0}, b...)
	}
	return b
}

func decodeBigInt(content []byte) (*big.Int, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("wire: empty INTEGER content")
	}
	negative := content[0]&0x80 != 0
	if !negative {
		return new(big.Int).SetBytes(content), nil
	}
	nBytes := len(content)
	mod := new(big.Int).Lsh(big.NewInt(1), uint(nBytes*8))
	raw := new(big.Int).SetBytes(content)
	return new(big.Int).Sub(raw, mod), nil
}

// --- OCTET STRING / UTF8String / BOOLEAN / NULL ----------------------------

func encodeBytes(buf *bytes.Buffer, class int, constructed bool, tag int, v []byte) {
	writeTagLen(buf, class, constructed, tag, len(v))
	buf.Write(v)
}

func encodeString(buf *bytes.Buffer, class int, constructed bool, tag int, v string) {
	encodeBytes(buf, class, constructed, tag, []byte(v))
}

func encodeBool(buf *bytes.Buffer, class int, constructed bool, tag int, v bool) {
	writeTagLen(buf, class, constructed, tag, 1)
	if v {
		buf.WriteByte(0xff)
	} else {
		buf.WriteByte(0x00)
	}
}

func decodeBool(content []byte) (bool, error) {
	if len(content) != 1 {
		return false, fmt.Errorf("wire: BOOLEAN content must be 1 byte, got %d", len(content))
	}
	return content[0] != 0, nil
}

func encodeNull(buf *bytes.Buffer, class int, constructed bool, tag int) {
	writeTagLen(buf, class, constructed, tag, 0)
}
