package cms

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
)

// Standard CMS attribute OIDs (RFC 5652, RFC 5911).
var (
	OIDData                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningTime          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	OIDTimestampToken       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	OIDCertificateRefs      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 21}
	OIDRevocationRefs       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 22}
	OIDCertificateValues    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 23}
	OIDRevocationValues     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}
	OIDSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

type essIssuerSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}
type essCertIDV2 struct {
	Algorithm    AlgorithmIdentifier `asn1:"optional"`
	Hash         []byte
	IssuerSerial essIssuerSerial `asn1:"optional"`
}
type signingCertificateV2 struct {
	Certificates []essCertIDV2
	Policies     asn1.RawValue `asn1:"optional"`
}

func signingCertificateAttribute(c *cert.Certificate, digestOID asn1.ObjectIdentifier) (Attribute, error) {
	h := newHashForOID(digestOID)
	if h == nil || c == nil || c.SerialNumber == nil {
		return Attribute{}, errors.New("cms: missing signing certificate or digest")
	}
	h.Write(c.Raw)
	issuer := c.Issuer.FullBytes
	if len(issuer) == 0 {
		var err error
		issuer, err = asn1.Marshal(c.Issuer)
		if err != nil {
			return Attribute{}, err
		}
	}
	id := essCertIDV2{
		Algorithm: AlgorithmIdentifier{Algorithm: digestOID},
		Hash:      h.Sum(nil),
		IssuerSerial: essIssuerSerial{
			Issuer: asn1.RawValue{FullBytes: marshalSEQ(marshalEXPLICIT(4, issuer))},
			Serial: c.SerialNumber,
		},
	}
	value, err := asn1.Marshal(signingCertificateV2{Certificates: []essCertIDV2{id}})
	if err != nil {
		return Attribute{}, err
	}
	return Attribute{Type: OIDSigningCertificateV2, Values: asn1.RawValue{FullBytes: marshalSETOF(value)}}, nil
}

func verifySigningCertificateAttribute(der []byte, c *cert.Certificate) error {
	var value signingCertificateV2
	remaining, err := asn1.Unmarshal(der, &value)
	if err != nil || len(remaining) != 0 || len(value.Certificates) == 0 {
		return errors.New("cms: malformed signing-certificate attribute")
	}
	id := value.Certificates[0]
	h := newHashForOID(id.Algorithm.Algorithm)
	if id.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}) {
		h = sha1.New()
	}
	// RFC 5035 omits hashAlgorithm when its default is SHA-256.
	if len(id.Algorithm.Algorithm) == 0 || id.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}) {
		h = sha256.New()
	}
	if h == nil {
		return errors.New("cms: unsupported signing-certificate hash")
	}
	h.Write(c.Raw)
	if !bytes.Equal(h.Sum(nil), id.Hash) {
		return errors.New("cms: signing-certificate hash mismatch")
	}
	if id.IssuerSerial.Serial != nil {
		if c.SerialNumber == nil || c.SerialNumber.Cmp(id.IssuerSerial.Serial) != 0 {
			return errors.New("cms: signing-certificate serial mismatch")
		}
		var names asn1.RawValue
		remaining, err = asn1.Unmarshal(id.IssuerSerial.Issuer.FullBytes, &names)
		if err != nil || len(remaining) != 0 || names.Tag != asn1.TagSequence {
			return errors.New("cms: malformed signing-certificate issuer")
		}
		matched := false
		remaining = names.Bytes
		for len(remaining) > 0 {
			var name asn1.RawValue
			remaining, err = asn1.Unmarshal(remaining, &name)
			if err != nil {
				return err
			}
			if name.Class == 2 && name.Tag == 4 && bytes.Equal(name.Bytes, c.Issuer.FullBytes) {
				matched = true
			}
		}
		if !matched {
			return errors.New("cms: signing-certificate issuer mismatch")
		}
	}
	return nil
}

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
		var stVal []byte
		stVal, err = asn1.Marshal(signingTime.UTC())
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
	var attrDERs [][]byte
	for _, a := range attrs {
		attrSeq, err := marshalAttribute(a)
		if err != nil {
			return nil, err
		}
		attrDERs = append(attrDERs, attrSeq)
	}
	// Wrap in SET OF (0x31)
	slices.SortFunc(attrDERs, bytes.Compare)
	return marshalSETOF(bytes.Join(attrDERs, nil)), nil
}

// marshalAttribute encodes one Attribute as SEQUENCE { OID, SET { raw } }.
func marshalAttribute(a Attribute) ([]byte, error) {
	oidDER, err := asn1.Marshal(a.Type)
	if err != nil {
		return nil, err
	}
	// Values.FullBytes already contains the SET { ... } bytes
	return marshalSEQ(slices.Concat(oidDER, a.Values.FullBytes)), nil
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
	switch {
	case l < 0x80:
		lenBytes = []byte{byte(l)}
	case l < 0x100:
		lenBytes = []byte{0x81, byte(l)}
	case l < 0x10000:
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	default:
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

func verifySigningCertificateV1(der []byte, c *cert.Certificate) error {
	var value struct {
		Certificates []struct {
			Hash         []byte
			IssuerSerial essIssuerSerial `asn1:"optional"`
		}
		Policies asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(der, &value); err != nil || len(rest) != 0 || len(value.Certificates) == 0 {
		return errors.New("cms: malformed SigningCertificate")
	}
	first := value.Certificates[0]
	encoded, err := asn1.Marshal(signingCertificateV2{Certificates: []essCertIDV2{{Algorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}}, Hash: first.Hash, IssuerSerial: first.IssuerSerial}}})
	if err != nil {
		return err
	}
	return verifySigningCertificateAttribute(encoded, c)
}
