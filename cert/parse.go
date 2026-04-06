package cert

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"crypto-dstu/dstu4145"
	"crypto-dstu/ec"
	"crypto-dstu/gf2m"
	"crypto-dstu/oid"
)

// Certificate holds a parsed Ukrainian X.509v3 certificate.
// Go's crypto/x509 cannot parse DSTU certificates — custom ASN.1 parsing required.
// Reference: cryptonite src/pkix/c/struct/pkix_utils.c, pkix_cert.c
type Certificate struct {
	Raw    []byte // original DER
	TBSRaw []byte // TBSCertificate DER (signed portion)

	Version      int
	SerialNumber *big.Int
	Issuer       asn1.RawValue
	Subject      asn1.RawValue
	NotBefore    time.Time
	NotAfter     time.Time

	PublicKey *dstu4145.PublicKey
	SigAlgOID asn1.ObjectIdentifier
	Signature []byte // raw BIT STRING bytes (no tag)

	Extensions []Extension

	// Ukrainian DN attributes extracted from Subject
	EDRPOU string
	DRFO   string
	IPN    string
	Email  string
	Title  string

	// Standard DN attributes
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Locality           string
	State              string
	GivenName          string
	Surname            string
}

// Extension mirrors crypto/x509/pkix.Extension without requiring that import.
type Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// --- internal ASN.1 structures ---

type tbsCertificate struct {
	Raw           asn1.RawContent
	Version       int `asn1:"optional,explicit,tag:0,default:0"`
	SerialNumber  *big.Int
	Signature     algorithmIdentifier
	Issuer        asn1.RawValue
	Validity      validity
	Subject       asn1.RawValue
	PublicKeyInfo subjectPublicKeyInfo
	Extensions    []rawExtension `asn1:"optional,explicit,tag:3"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type rawExtension struct {
	Id       asn1.ObjectIdentifier
	Critical bool   `asn1:"optional"`
	Value    []byte // OCTET STRING
}

type outerCertificate struct {
	Raw                asn1.RawContent
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	Signature          asn1.BitString
}

// ParseCertificate parses a DER-encoded Ukrainian X.509v3 certificate.
func ParseCertificate(der []byte) (*Certificate, error) {
	var outer outerCertificate
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, errors.New("cert: ParseCertificate: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("cert: ParseCertificate: trailing data")
	}

	var tbs tbsCertificate
	if _, err := asn1.Unmarshal(outer.TBSCertificate.FullBytes, &tbs); err != nil {
		return nil, errors.New("cert: ParseCertificate: TBS: " + err.Error())
	}

	c := &Certificate{
		Raw:          der,
		TBSRaw:       outer.TBSCertificate.FullBytes,
		Version:      tbs.Version + 1,
		SerialNumber: tbs.SerialNumber,
		Issuer:       tbs.Issuer,
		Subject:      tbs.Subject,
		NotBefore:    tbs.Validity.NotBefore,
		NotAfter:     tbs.Validity.NotAfter,
		SigAlgOID:    outer.SignatureAlgorithm.Algorithm,
		Signature:    outer.Signature.Bytes,
	}

	for _, ext := range tbs.Extensions {
		c.Extensions = append(c.Extensions, Extension(ext))
	}

	if err := parseSubjectDN(c); err != nil {
		return nil, err
	}

	if err := parsePublicKey(c, tbs.PublicKeyInfo); err != nil {
		return nil, err
	}

	return c, nil
}

// ParseCertificates parses one or more concatenated DER certificates.
func ParseCertificates(der []byte) ([]*Certificate, error) {
	var certs []*Certificate
	for len(der) > 0 {
		c, err := ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
		der = der[len(c.Raw):]
	}
	return certs, nil
}

// parseSubjectDN extracts standard and Ukrainian-specific attributes from Subject DN.
// Subject RawValue.FullBytes is the outer SEQUENCE; its .Bytes is the content.
// Structure: SEQUENCE { SET { SEQUENCE { OID, Value } } ... }
func parseSubjectDN(c *Certificate) error {
	// Unmarshal the outer SEQUENCE content to get individual SET (RDN) elements.
	// We use the inner Bytes (not FullBytes) to iterate over the SET elements.
	rest := c.Subject.Bytes
	for len(rest) > 0 {
		var rdn asn1.RawValue
		var err error
		rest, err = asn1.UnmarshalWithParams(rest, &rdn, "set")
		if err != nil {
			// Try without set tag — some encoders use SEQUENCE for RDN
			var rv asn1.RawValue
			rest2, err2 := asn1.Unmarshal(rest, &rv)
			if err2 != nil {
				break
			}
			rest = rest2
			rdn = rv
		}
		// rdn.Bytes is the content of the SET — a sequence of ATAVs
		atvRest := rdn.Bytes
		for len(atvRest) > 0 {
			var atav asn1.RawValue
			var err error
			atvRest, err = asn1.Unmarshal(atvRest, &atav)
			if err != nil {
				break
			}
			parseATAV(c, atav)
		}
	}
	return nil
}

// parseATAV parses a single AttributeTypeAndValue into Certificate fields.
func parseATAV(c *Certificate, raw asn1.RawValue) {
	var atv struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	if _, err := asn1.Unmarshal(raw.FullBytes, &atv); err != nil {
		return
	}
	val := extractString(atv.Value)

	switch {
	case atv.Type.Equal(oid.EDRPOU):
		c.EDRPOU = val
	case atv.Type.Equal(oid.DRFO):
		c.DRFO = val
	case atv.Type.Equal(oid.IPN):
		c.IPN = val
	case atv.Type.Equal(oid.OIDEmailAddress):
		c.Email = val
	case atv.Type.Equal(oid.OIDTitle):
		c.Title = val
	case atv.Type.Equal(oid.OIDCommonName):
		c.CommonName = val
	case atv.Type.Equal(oid.OIDOrganization):
		c.Organization = val
	case atv.Type.Equal(oid.OIDOrganizationalUnit):
		c.OrganizationalUnit = val
	case atv.Type.Equal(oid.OIDCountry):
		c.Country = val
	case atv.Type.Equal(oid.OIDLocality):
		c.Locality = val
	case atv.Type.Equal(oid.OIDState):
		c.State = val
	case atv.Type.Equal(oid.OIDGivenName):
		c.GivenName = val
	case atv.Type.Equal(oid.OIDSurname):
		c.Surname = val
	}
}

// extractString returns the string value from a RawValue (UTF8String, PrintableString, IA5String, etc.)
func extractString(rv asn1.RawValue) string {
	var s string
	if _, err := asn1.Unmarshal(rv.FullBytes, &s); err == nil {
		return s
	}
	return string(rv.Bytes)
}

// parsePublicKey extracts and parses the DSTU 4145 public key from SubjectPublicKeyInfo.
//
// Three encoding styles are supported:
//  1. algorithm.OID = curve OID directly (synthetic test certs).
//  2. algorithm.OID = sig-alg OID, Parameters = curve OID (older encoding).
//  3. algorithm.OID = sig-alg OID, Parameters = SEQUENCE { DSTU domain params }
//     and BIT STRING = OCTET STRING { LE compressed point } (real CZO certs).
func parsePublicKey(c *Certificate, spki subjectPublicKeyInfo) error {
	algOID := spki.Algorithm.Algorithm
	params := dstu4145.ParamsByOID(algOID)
	if params == nil {
		// Try parameters as bare curve OID
		var curveOID asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID); err == nil {
			params = dstu4145.ParamsByOID(curveOID)
		}
	}
	if params == nil {
		// Try parameters as DSTU domain-params SEQUENCE: extract field size m to find curve.
		params = paramsFromDSTUDomainParams(spki.Algorithm.Parameters.FullBytes)
	}
	if params == nil {
		// Not a DSTU key — store nil PublicKey (non-fatal)
		return nil
	}

	keyBytes := spki.PublicKey.Bytes
	if len(keyBytes) == 0 {
		return errors.New("cert: empty public key bytes")
	}
	// Real CZO certs wrap the key as OCTET STRING inside the BIT STRING.
	if keyBytes[0] == 0x04 && len(keyBytes) >= 2 {
		inner := keyBytes[1:]
		expectedLen := (params.Curve.M + 7) / 8
		if len(inner) >= 1 && int(inner[0]) == expectedLen {
			// Looks like OCTET STRING { LE key }
			keyBytes = inner[1:]
		}
	}

	pub, err := expandPublicKey(params.Curve, keyBytes)
	if err != nil {
		return errors.New("cert: public key expansion: " + err.Error())
	}
	c.PublicKey = pub
	return nil
}

// paramsFromDSTUDomainParams extracts the DSTU curve parameters from a DSTU
// domain-parameters SEQUENCE by reading the field size m (first INTEGER in the
// inner EC_PARAMS SEQUENCE) and looking up the matching named curve.
//
// DSTU domain params DER layout (abbreviated):
//
//	SEQUENCE {          ← outer wrapper (may be present)
//	  SEQUENCE {        ← EC_PARAMS
//	    INTEGER m       ← GF(2^m) field degree, e.g. 257
//	    INTEGER ks      ← reduction polynomial
//	    ...
//	  }
//	  ...
//	}
func paramsFromDSTUDomainParams(b []byte) *dstu4145.DomainParams {
	if len(b) < 4 {
		return nil
	}
	// DSTU domain params have nested SEQUENCE wrappers. Unwrap SEQUENCE layers
	// until we find the first INTEGER (field degree m).
	// Typical layout: SEQUENCE { SEQUENCE { SEQUENCE { INTEGER m, ... }, ... }, ... }
	rest := b
	for len(rest) >= 2 {
		switch rest[0] {
		case 0x30: // SEQUENCE — unwrap and descend
			var seq asn1.RawValue
			if _, err := asn1.Unmarshal(rest, &seq); err != nil {
				return nil
			}
			rest = seq.Bytes
		case 0x02: // INTEGER — this is m
			var m int
			if _, err := asn1.Unmarshal(rest, &m); err != nil {
				return nil
			}
			for _, p := range dstu4145.AllParams() {
				if p.Curve.M == m {
					return &p
				}
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

// expandPublicKey parses a DSTU public key from compressed (≤ ceil(m/8) bytes)
// or uncompressed (≤ 2*ceil(m/8) bytes) encoding.
//
// Byte order handling:
//   - Real cryptonite certs: x-coordinate stored little-endian → reverse to BE before Expand.
//   - Synthetic test certs: x-coordinate stored big-endian (direct Compress() output).
//
// Strategy: try BE directly first; if Expand fails, try LE→BE reversal.
// For the uncompressed case, coordinates are always treated as LE (real cert convention).
func expandPublicKey(curve *ec.Curve, data []byte) (*dstu4145.PublicKey, error) {
	byteLen := (curve.M + 7) / 8
	words := (curve.M + 31) / 32

	switch {
	case len(data) <= byteLen:
		// Try interpreting as BE first (synthetic test certs use Compress() directly).
		padded := bePad(data, byteLen)
		if pt, err := curve.Expand(padded); err == nil {
			return &dstu4145.PublicKey{Q: pt, Curve: curve}, nil
		}
		// Fall back to LE→BE (real cryptonite cert encoding).
		be := leReverse(lePad(data, byteLen))
		pt, err := curve.Expand(be)
		if err != nil {
			return nil, err
		}
		return &dstu4145.PublicKey{Q: pt, Curve: curve}, nil

	case len(data) <= 2*byteLen:
		// Uncompressed: x LE || y LE (real cert convention).
		half := len(data) / 2
		x := gf2m.FromBytes(leReverse(lePad(data[:half], byteLen)), words)
		y := gf2m.FromBytes(leReverse(lePad(data[half:], byteLen)), words)
		pt := &ec.Point{X: x, Y: y, Curve: curve}
		if !curve.Contains(pt) {
			return nil, errors.New("point not on curve")
		}
		return &dstu4145.PublicKey{Q: pt, Curve: curve}, nil

	default:
		return nil, errors.New("unexpected public key length")
	}
}

// bePad zero-pads a big-endian byte slice to exactly n bytes by prepending zeros.
func bePad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// lePad zero-pads a little-endian byte slice to exactly n bytes by appending zeros.
func lePad(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

// leReverse returns a copy of b with bytes in reversed order (LE ↔ BE).
func leReverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
