package cms

import (
	"encoding/asn1"
	"errors"
	"time"
)

// Standard CMS attribute OIDs (RFC 5652, RFC 5911).
var (
	OIDData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDTimestampToken    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	OIDCertificateRefs   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 21}
	OIDRevocationRefs    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 22}
	OIDCertificateValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}
	OIDRevocationValues  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}
)

// Attribute is a CMS attribute: a type OID with one or more values.
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// BuildSignedAttrs constructs the standard signed attributes for a CMS SignerInfo:
//   - id-contentType  → contentType OID
//   - id-messageDigest → hash of the content
//   - id-signingTime   → current UTC time (if non-zero)
func BuildSignedAttrs(contentType asn1.ObjectIdentifier, digest []byte, signingTime time.Time) ([]Attribute, error) {
	// 1. content-type attribute
	ctVal, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, errors.New("cms: marshal contentType: " + err.Error())
	}

	// 2. message-digest attribute
	mdVal, err := asn1.Marshal(digest)
	if err != nil {
		return nil, errors.New("cms: marshal messageDigest: " + err.Error())
	}

	attrs := []Attribute{
		{
			Type:   OIDContentType,
			Values: asn1.RawValue{FullBytes: marshalSetOf(ctVal)},
		},
		{
			Type:   OIDMessageDigest,
			Values: asn1.RawValue{FullBytes: marshalSetOf(mdVal)},
		},
	}

	// 3. signing-time attribute (optional)
	if !signingTime.IsZero() {
		stVal, err := asn1.Marshal(signingTime.UTC())
		if err != nil {
			return nil, errors.New("cms: marshal signingTime: " + err.Error())
		}
		attrs = append(attrs, Attribute{
			Type:   OIDSigningTime,
			Values: asn1.RawValue{FullBytes: marshalSetOf(stVal)},
		})
	}

	return attrs, nil
}

// MarshalSignedAttrs DER-encodes a slice of Attributes as a SET OF (tag 0x31).
// This is the byte string that gets signed (RFC 5652 §5.4).
func MarshalSignedAttrs(attrs []Attribute) ([]byte, error) {
	// Each attribute: SEQUENCE { OID, SET { value } }
	var attrDERs []byte
	for _, a := range attrs {
		attrSeq, err := marshalAttribute(a)
		if err != nil {
			return nil, err
		}
		attrDERs = append(attrDERs, attrSeq...)
	}
	// Wrap in SET OF (0x31)
	return marshalSETOF(attrDERs), nil
}

// marshalAttribute encodes one Attribute as SEQUENCE { OID, SET { raw } }.
func marshalAttribute(a Attribute) ([]byte, error) {
	oidDER, err := asn1.Marshal(a.Type)
	if err != nil {
		return nil, err
	}
	// Values.FullBytes already contains the SET { ... } bytes
	seq := append(oidDER, a.Values.FullBytes...)
	return marshalSEQ(seq), nil
}

// marshalSetOf wraps a single DER value in SET OF { val } (tag 0x31).
func marshalSetOf(val []byte) []byte {
	return marshalSETOF(val)
}

// marshalSETOF wraps content bytes in a SET OF TLV (tag 0x31).
func marshalSETOF(content []byte) []byte {
	return tlv(0x31, content)
}

// marshalSEQ wraps content bytes in a SEQUENCE TLV (tag 0x30).
func marshalSEQ(content []byte) []byte {
	return tlv(0x30, content)
}

// tlv encodes a DER TLV with the given tag byte and content.
func tlv(tag byte, content []byte) []byte {
	l := len(content)
	var lenBytes []byte
	if l < 0x80 {
		lenBytes = []byte{byte(l)}
	} else if l < 0x100 {
		lenBytes = []byte{0x81, byte(l)}
	} else if l < 0x10000 {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	} else {
		lenBytes = []byte{0x83, byte(l >> 16), byte(l >> 8), byte(l)}
	}
	out := make([]byte, 1+len(lenBytes)+l)
	out[0] = tag
	copy(out[1:], lenBytes)
	copy(out[1+len(lenBytes):], content)
	return out
}

// FindAttribute returns the raw DER value bytes of the first attribute with the given OID, or nil.
func FindAttribute(attrs []Attribute, oid asn1.ObjectIdentifier) []byte {
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			return a.Values.FullBytes
		}
	}
	return nil
}
