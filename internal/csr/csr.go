// Package csr implements PKCS#10 Certificate Signing Requests (RFC 2986)
// for Ukrainian DSTU 4145 keys.
// Reference: cryptonite src/pkix/c/engine/certificate_request_engine.c
package csr

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

// --- ASN.1 structures (RFC 2986) ---

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type certificationRequestInfo struct {
	Version   int
	Subject   asn1.RawValue
	PublicKey subjectPublicKeyInfo
	// Attributes [0] IMPLICIT Attributes OPTIONAL
	Attributes asn1.RawValue `asn1:"tag:0,optional"`
}

type certificationRequest struct {
	CertificationRequestInfo asn1.RawValue
	SignatureAlgorithm       algorithmIdentifier
	Signature                asn1.BitString
}

// AttributeTypeAndValue holds a single DN attribute.
type AttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value string
}

// Request holds the inputs for building a PKCS#10 CSR.
type Request struct {
	// Subject DN attributes in order.
	// Use oid.OIDCommonName, oid.EDRPOU, oid.DRFO etc. as Type.
	Subject []AttributeTypeAndValue
	// SignatureAlgorithmOID overrides the default derived from the key's curve.
	// Leave nil to use the curve's recommended hash OID (GOST34311 or Kupyna256).
	SignatureAlgorithmOID asn1.ObjectIdentifier
}

// Create builds, signs, and returns a DER-encoded PKCS#10 CSR.
func Create(req *Request, priv *dstu4145.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve == nil {
		return nil, errors.New("csr: missing private key")
	}
	if priv.Curve.IsONB() {
		return nil, errors.New("csr: ONB CSR profile is not supported")
	}
	privKey := priv

	// Determine signature algorithm OID.
	sigAlgOID := req.SignatureAlgorithmOID
	if sigAlgOID == nil {
		params := dstu4145.ParamsByOID(curveOIDForKey(privKey))
		if params == nil {
			return nil, errors.New("csr: cannot determine curve OID for key")
		}
		sigAlgOID = params.HashOID
	}

	// Build Subject DER (SEQUENCE of SET of SEQUENCE{OID, UTF8String}).
	subjectDER, err := buildSubjectDER(req.Subject)
	if err != nil {
		return nil, errors.New("csr: building subject: " + err.Error())
	}

	// Build SubjectPublicKeyInfo.
	spki, err := buildSPKI(privKey)
	if err != nil {
		return nil, errors.New("csr: building SPKI: " + err.Error())
	}

	// Build CertificationRequestInfo DER.
	criDER, err := buildCRI(subjectDER, spki)
	if err != nil {
		return nil, errors.New("csr: building CRI: " + err.Error())
	}

	// Hash the CRI.
	digest, err := hashData(criDER, sigAlgOID)
	if err != nil {
		return nil, err
	}

	// Sign.
	sigDER, err := priv.Sign(rand.Reader, digest, crypto.Hash(0))
	if err != nil {
		return nil, errors.New("csr: signing: " + err.Error())
	}

	// Encode the outer CertificationRequest.
	cr := certificationRequest{
		CertificationRequestInfo: asn1.RawValue{FullBytes: criDER},
		SignatureAlgorithm: algorithmIdentifier{
			Algorithm: sigAlgOID,
		},
		Signature: asn1.BitString{Bytes: sigDER, BitLength: len(sigDER) * 8},
	}
	return asn1.Marshal(cr)
}

// ParsedRequest holds the result of parsing a DER-encoded PKCS#10 CSR.
type ParsedRequest struct {
	Raw             []byte
	CRIRaw          []byte // DER of CertificationRequestInfo (signed portion)
	Subject         []AttributeTypeAndValue
	PublicKey       *dstu4145.PublicKey
	SignatureAlgOID asn1.ObjectIdentifier
	SignatureBytes  []byte
}

// Parse parses a DER-encoded PKCS#10 CertificationRequest.
func Parse(der []byte) (*ParsedRequest, error) {
	var cr certificationRequest
	rest, err := asn1.Unmarshal(der, &cr)
	if err != nil {
		return nil, errors.New("csr: parse: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("csr: parse: trailing data")
	}

	criRaw := cr.CertificationRequestInfo.FullBytes

	var cri certificationRequestInfo
	if _, err = asn1.Unmarshal(criRaw, &cri); err != nil {
		return nil, errors.New("csr: parse CRI: " + err.Error())
	}

	subject := parseSubject(cri.Subject)

	pub, err := parsePublicKeyFromSPKI(cri.PublicKey)
	if err != nil {
		return nil, errors.New("csr: parse public key: " + err.Error())
	}

	return &ParsedRequest{
		Raw:             der,
		CRIRaw:          criRaw,
		Subject:         subject,
		PublicKey:       pub,
		SignatureAlgOID: cr.SignatureAlgorithm.Algorithm,
		SignatureBytes:  cr.Signature.Bytes,
	}, nil
}

// Verify checks the self-signature on the parsed CSR.
func (r *ParsedRequest) Verify() error {
	if r.PublicKey == nil {
		return errors.New("csr: verify: no public key")
	}

	digest, err := hashData(r.CRIRaw, r.SignatureAlgOID)
	if err != nil {
		return errors.New("csr: verify: hash: " + err.Error())
	}

	sig, err := dstu4145.UnmarshalSignature(r.SignatureBytes, r.PublicKey.Curve.Words)
	if err != nil {
		return errors.New("csr: verify: unmarshal signature: " + err.Error())
	}

	if !dstu4145.Verify(r.PublicKey, digest, sig) {
		return errors.New("csr: verify: signature verification failed")
	}
	return nil
}

// --- helpers ---

// buildSubjectDER encodes a list of AttributeTypeAndValue into a DER Subject SEQUENCE.
func buildSubjectDER(attrs []AttributeTypeAndValue) ([]byte, error) {
	// Each attr → SEQUENCE { OID, UTF8String }
	// Wrapped in SET, then all SETs wrapped in outer SEQUENCE.
	var rdns []asn1.RawValue
	for _, a := range attrs {
		atavDER, err := asn1.Marshal(struct {
			Type  asn1.ObjectIdentifier
			Value string `asn1:"utf8"`
		}{Type: a.Type, Value: a.Value})
		if err != nil {
			return nil, err
		}
		// Wrap single ATAV in a SET.
		setDER, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      atavDER,
		})
		if err != nil {
			return nil, err
		}
		rdns = append(rdns, asn1.RawValue{FullBytes: setDER})
	}

	// Outer SEQUENCE.
	var seqBytes []byte
	for _, r := range rdns {
		seqBytes = append(seqBytes, r.FullBytes...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seqBytes,
	})
}

// buildSPKI builds a SubjectPublicKeyInfo for a DSTU 4145 public key.
// Encoding: algorithm = DSTU4145WithGOST34311 + curve OID parameter;
// public key = compressed point (x-coordinate, big-endian, zero-padded to ceil(m/8)).
func buildSPKI(priv *dstu4145.PrivateKey) (subjectPublicKeyInfo, error) {
	pub := priv.Public()
	curveOID := curveOIDForKey(priv)
	if curveOID == nil {
		return subjectPublicKeyInfo{}, errors.New("csr: unknown curve OID")
	}

	byteLen := (priv.Curve.M + 7) / 8
	// Encode as uncompressed x||y (each padded BE) so Verify can recover exact point.
	xBytes := pub.Q.X.Bytes()
	yBytes := pub.Q.Y.Bytes()
	keyBytes := make([]byte, 2*byteLen)
	if len(xBytes) >= byteLen {
		copy(keyBytes[:byteLen], xBytes[len(xBytes)-byteLen:])
	} else {
		copy(keyBytes[byteLen-len(xBytes):byteLen], xBytes)
	}
	if len(yBytes) >= byteLen {
		copy(keyBytes[byteLen:], yBytes[len(yBytes)-byteLen:])
	} else {
		copy(keyBytes[2*byteLen-len(yBytes):], yBytes)
	}

	curveOIDRaw, err := asn1.Marshal(curveOID)
	if err != nil {
		return subjectPublicKeyInfo{}, err
	}

	return subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oid.DSTU4145WithGOST34311,
			Parameters: asn1.RawValue{FullBytes: curveOIDRaw},
		},
		PublicKey: asn1.BitString{Bytes: keyBytes, BitLength: len(keyBytes) * 8},
	}, nil
}

// buildCRI builds the DER-encoded CertificationRequestInfo.
func buildCRI(subjectDER []byte, spki subjectPublicKeyInfo) ([]byte, error) {
	cri := struct {
		Version   int
		Subject   asn1.RawValue
		PublicKey subjectPublicKeyInfo
	}{
		Version:   0,
		Subject:   asn1.RawValue{FullBytes: subjectDER},
		PublicKey: spki,
	}
	return asn1.Marshal(cri)
}

// hashData hashes data using the algorithm indicated by sigAlgOID.
func hashData(data []byte, sigAlgOID asn1.ObjectIdentifier) ([]byte, error) {
	switch {
	case sigAlgOID.Equal(oid.DSTU4145WithGOST34311):
		h := gost34311.New()
		_, _ = h.Write(data)
		return h.Sum(nil), nil
	case sigAlgOID.Equal(oid.DSTU4145WithKupyna256):
		h := kupyna.New256()
		_, _ = h.Write(data)
		return h.Sum(nil), nil
	case sigAlgOID.Equal(oid.DSTU4145WithKupyna512):
		h := kupyna.New512()
		_, _ = h.Write(data)
		return h.Sum(nil), nil
	default:
		return nil, errors.New("csr: unsupported signature algorithm: " + sigAlgOID.String())
	}
}

// curveOIDForKey returns the OID for the curve used by priv.
// Curves are identified by their field degree M and order N (not pointer equality).
func curveOIDForKey(priv *dstu4145.PrivateKey) asn1.ObjectIdentifier {
	for _, p := range dstu4145.AllParams() {
		if p.Curve.EqualDomain(priv.Curve) {
			return p.OID
		}
	}
	return nil
}

// parseSubject decodes an ASN.1 Subject RawValue into []AttributeTypeAndValue.
func parseSubject(raw asn1.RawValue) []AttributeTypeAndValue {
	var attrs []AttributeTypeAndValue
	rest := raw.Bytes
	for len(rest) > 0 {
		var setVal asn1.RawValue
		var err error
		rest, err = asn1.UnmarshalWithParams(rest, &setVal, "set")
		if err != nil {
			// Try without "set" tag hint
			var rv asn1.RawValue
			rest2, err2 := asn1.Unmarshal(rest, &rv)
			if err2 != nil {
				break
			}
			rest = rest2
			setVal = rv
		}
		atvRest := setVal.Bytes
		for len(atvRest) > 0 {
			var atav struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}
			var err2 error
			atvRest, err2 = asn1.Unmarshal(atvRest, &atav)
			if err2 != nil {
				break
			}
			val := extractStringRaw(atav.Value)
			attrs = append(attrs, AttributeTypeAndValue{Type: atav.Type, Value: val})
		}
	}
	return attrs
}

// extractStringRaw returns the string value from a RawValue.
func extractStringRaw(rv asn1.RawValue) string {
	var s string
	if _, err := asn1.Unmarshal(rv.FullBytes, &s); err == nil {
		return s
	}
	return string(rv.Bytes)
}

// parsePublicKeyFromSPKI extracts a DSTU 4145 public key from SubjectPublicKeyInfo.
// Supports uncompressed encoding (2*byteLen bytes = x||y) and compressed (byteLen bytes).
func parsePublicKeyFromSPKI(spki subjectPublicKeyInfo) (*dstu4145.PublicKey, error) {
	algOID := spki.Algorithm.Algorithm

	// Try algorithm OID as curve OID directly.
	params := dstu4145.ParamsByOID(algOID)
	if params == nil {
		// Try parameters as bare curve OID.
		var curveOID asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID); err == nil {
			params = dstu4145.ParamsByOID(curveOID)
		}
	}
	if params == nil {
		return nil, errors.New("csr: unknown public key algorithm/curve")
	}

	keyBytes := spki.PublicKey.Bytes
	if len(keyBytes) == 0 {
		return nil, errors.New("csr: empty public key")
	}

	byteLen := (params.Curve.M + 7) / 8
	words := params.Curve.Words

	// Uncompressed: exactly 2*byteLen bytes → x (BE) || y (BE).
	if len(keyBytes) >= 2*byteLen {
		x := gf2m.FromBytes(keyBytes[:byteLen], words)
		y := gf2m.FromBytes(keyBytes[byteLen:2*byteLen], words)
		pt := &ec.Point{X: x, Y: y, Curve: params.Curve}
		if !params.Curve.Contains(pt) {
			return nil, errors.New("csr: uncompressed public key not on curve")
		}
		return &dstu4145.PublicKey{Q: pt, Curve: params.Curve}, nil
	}

	// Compressed: byteLen bytes → recover y via Expand.
	padded := make([]byte, byteLen)
	if len(keyBytes) < byteLen {
		copy(padded[byteLen-len(keyBytes):], keyBytes)
	} else {
		copy(padded, keyBytes[:byteLen])
	}
	pt, err := params.Curve.Expand(padded)
	if err != nil {
		return nil, errors.New("csr: expand public key: " + err.Error())
	}
	return &dstu4145.PublicKey{Q: pt, Curve: params.Curve}, nil
}
