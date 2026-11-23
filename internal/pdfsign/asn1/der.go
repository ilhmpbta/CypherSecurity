package asn1

import (
	"bytes"
	"errors"
	"math/big"
	"time"
)

// DER Tags
const (
	TagBoolean         = 0x01
	TagInteger         = 0x02
	TagBitString       = 0x03
	TagOctetString     = 0x04
	TagNull            = 0x05
	TagOID             = 0x06
	TagUTF8String      = 0x0C
	TagPrintableString = 0x13
	TagUTCTime         = 0x17
	TagGeneralizedTime = 0x18
	TagSequence        = 0x30
	TagSet             = 0x31
)

var ErrInvalidDER = errors.New("asn1: invalid DER encoding")

// EncodeLength encodes a DER length bytes payload.
func EncodeLength(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	} else if l < 256 {
		return []byte{0x81, byte(l)}
	} else if l < 65536 {
		return []byte{0x82, byte(l >> 8), byte(l)}
	} else if l < 16777216 {
		return []byte{0x83, byte(l >> 16), byte(l >> 8), byte(l)}
	}
	return []byte{0x84, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
}

// EncodeTagAndLength wraps content bytes with a tag and DER length.
func EncodeTagAndLength(tag byte, content []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(tag)
	buf.Write(EncodeLength(len(content)))
	buf.Write(content)
	return buf.Bytes()
}

// EncodeInteger encodes an int64 as a DER INTEGER.
func EncodeInteger(n int64) []byte {
	return EncodeBigInt(big.NewInt(n))
}

// EncodeBigInt encodes a big.Int as a DER INTEGER.
func EncodeBigInt(n *big.Int) []byte {
	if n == nil {
		n = big.NewInt(0)
	}
	bytesVal := n.Bytes()
	if len(bytesVal) == 0 {
		bytesVal = []byte{0x00}
	} else if (bytesVal[0] & 0x80) != 0 {
		// Prepend 0x00 if highest bit is set to avoid negative interpretation
		padded := make([]byte, len(bytesVal)+1)
		padded[0] = 0x00
		copy(padded[1:], bytesVal)
		bytesVal = padded
	}
	return EncodeTagAndLength(TagInteger, bytesVal)
}

// EncodeOctetString encodes raw bytes as a DER OCTET STRING.
func EncodeOctetString(b []byte) []byte {
	if b == nil {
		b = []byte{}
	}
	return EncodeTagAndLength(TagOctetString, b)
}

// EncodeBitString encodes raw bytes as a DER BIT STRING (with 0 unused bits).
func EncodeBitString(b []byte) []byte {
	if b == nil {
		b = []byte{}
	}
	content := make([]byte, len(b)+1)
	content[0] = 0x00 // 0 unused bits
	copy(content[1:], b)
	return EncodeTagAndLength(TagBitString, content)
}

// EncodeOID encodes an integer slice OID into DER format.
func EncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return EncodeTagAndLength(TagOID, []byte{})
	}
	var body bytes.Buffer
	body.WriteByte(byte(oid[0]*40 + oid[1]))
	for _, val := range oid[2:] {
		body.Write(encodeBase128(uint64(val)))
	}
	return EncodeTagAndLength(TagOID, body.Bytes())
}

func encodeBase128(n uint64) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	var buf []byte
	first := true
	for n > 0 {
		b := byte(n & 0x7F)
		if !first {
			b |= 0x80
		}
		buf = append([]byte{b}, buf...)
		n >>= 7
		first = false
	}
	return buf
}

// EncodeSequence encodes multiple DER byte elements into a DER SEQUENCE.
func EncodeSequence(elements ...[]byte) []byte {
	var buf bytes.Buffer
	for _, el := range elements {
		buf.Write(el)
	}
	return EncodeTagAndLength(TagSequence, buf.Bytes())
}

// EncodeSet encodes multiple DER byte elements into a DER SET.
func EncodeSet(elements ...[]byte) []byte {
	var buf bytes.Buffer
	for _, el := range elements {
		buf.Write(el)
	}
	return EncodeTagAndLength(TagSet, buf.Bytes())
}

// EncodeContextSpecific encodes content as a context-specific tagged element ([tagNum]).
func EncodeContextSpecific(tagNum int, constructed bool, content []byte) []byte {
	tag := byte(0x80 | tagNum)
	if constructed {
		tag |= 0x20
	}
	if content == nil {
		content = []byte{}
	}
	return EncodeTagAndLength(tag, content)
}

// EncodeUTCTime encodes a time.Time as DER UTCTime.
func EncodeUTCTime(t time.Time) []byte {
	s := t.UTC().Format("060102150405Z")
	return EncodeTagAndLength(TagUTCTime, []byte(s))
}

// EncodeNull encodes a DER NULL.
func EncodeNull() []byte {
	return []byte{TagNull, 0x00}
}

// DERElem represents a parsed DER element.
type DERElem struct {
	Tag     byte
	Content []byte
	Full    []byte
}

// DecodeDER parses the first DER element from data.
func DecodeDER(data []byte) (DERElem, []byte, error) {
	if len(data) < 2 {
		return DERElem{}, nil, ErrInvalidDER
	}
	tag := data[0]
	length, lenBytes, err := parseLength(data[1:])
	if err != nil {
		return DERElem{}, nil, err
	}
	totalHeader := 1 + lenBytes
	if len(data) < totalHeader+length {
		return DERElem{}, nil, ErrInvalidDER
	}
	content := data[totalHeader : totalHeader+length]
	full := data[:totalHeader+length]
	rest := data[totalHeader+length:]
	return DERElem{Tag: tag, Content: content, Full: full}, rest, nil
}

func parseLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrInvalidDER
	}
	b := data[0]
	if (b & 0x80) == 0 {
		return int(b), 1, nil
	}
	numBytes := int(b & 0x7F)
	if numBytes == 0 || numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0, ErrInvalidDER
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}
