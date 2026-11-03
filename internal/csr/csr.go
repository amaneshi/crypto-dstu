// Package csr implements PKCS#10 Certificate Signing Requests (RFC 2986)
// for Ukrainian DSTU 4145 keys.
// Reference: cryptonite src/pkix/c/engine/certificate_request_engine.c
package csr

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
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
	// Required for national output; absent only in legacy library requests.
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
	// Leave nil to use the curve's GOST PB/ONB signature algorithm.
	SignatureAlgorithmOID asn1.ObjectIdentifier
}

// Create builds, signs, and returns a DER-encoded PKCS#10 CSR.
func Create(req *Request, priv *dstu4145.PrivateKey) ([]byte, error) {
	if req == nil || priv == nil || priv.Curve == nil || priv.D == nil {
		return nil, errors.New("csr: missing request or private key")
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(new(big.Int).SetBytes(priv.Curve.N)) >= 0 {
		return nil, errors.New("csr: private scalar out of range")
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
	if err := checkSignatureProfile(sigAlgOID, priv.Curve); err != nil {
		return nil, err
	}

	// Build Subject DER (SEQUENCE of SET of SEQUENCE{OID, UTF8String}).
	subjectDER, err := buildSubjectDER(req.Subject)
	if err != nil {
		return nil, errors.New("csr: building subject: " + err.Error())
	}

	// Build SubjectPublicKeyInfo.
	spki, err := buildNationalSPKI(privKey, sigAlgOID)
	if err != nil {
		return nil, errors.New("csr: building SPKI: " + err.Error())
	}

	// Build CertificationRequestInfo DER.
	criDER, err := buildCRI(subjectDER, spki)
	if err != nil {
		return nil, errors.New("csr: building CRI: " + err.Error())
	}

	// Hash the CRI.
	digest, err := hashNational(criDER, sigAlgOID)
	if err != nil {
		return nil, err
	}

	// Sign.
	sig, err := dstu4145.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, errors.New("csr: signing: " + err.Error())
	}
	rawSignature, err := dstu4145.MarshalSignatureRaw(sig, priv.Curve)
	if err != nil {
		return nil, err
	}
	sigDER, err := asn1.Marshal(rawSignature)
	if err != nil {
		return nil, err
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
	national        bool
}

// Parse parses a DER-encoded PKCS#10 CertificationRequest.
func Parse(der []byte) (*ParsedRequest, error) {
	if len(der) == 0 || len(der) > 1<<20 {
		return nil, errors.New("csr: invalid request size")
	}
	var cr certificationRequest
	rest, err := asn1.Unmarshal(der, &cr)
	if err != nil {
		return nil, errors.New("csr: parse: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("csr: parse: trailing data")
	}
	canonical, err := asn1.Marshal(cr)
	if err != nil || !bytes.Equal(canonical, der) || cr.Signature.BitLength != len(cr.Signature.Bytes)*8 {
		return nil, errors.New("csr: malformed request encoding")
	}

	criRaw := cr.CertificationRequestInfo.FullBytes

	var cri certificationRequestInfo
	if rest, parseErr := asn1.Unmarshal(criRaw, &cri); parseErr != nil || len(rest) != 0 {
		return nil, errors.New("csr: malformed request information")
	}
	canonical, err = asn1.Marshal(cri)
	if err != nil || !bytes.Equal(canonical, criRaw) || cri.Version != 0 {
		return nil, errors.New("csr: unsupported or malformed request information")
	}
	if err = validateRequestInfo(cri); err != nil {
		return nil, err
	}

	subject := parseSubject(cri.Subject)

	pub, national, err := parseNationalOrLegacySPKI(cri.PublicKey)
	if err != nil {
		return nil, errors.New("csr: parse public key: " + err.Error())
	}
	if err = checkSignatureProfile(cr.SignatureAlgorithm.Algorithm, pub.Curve); err != nil {
		return nil, err
	}
	if len(cr.SignatureAlgorithm.Parameters.FullBytes) != 0 && !bytes.Equal(cr.SignatureAlgorithm.Parameters.FullBytes, []byte{5, 0}) {
		return nil, errors.New("csr: unsupported signature parameters")
	}
	if national && (!consistentNationalAlgorithms(cri.PublicKey.Algorithm.Algorithm, cr.SignatureAlgorithm.Algorithm) || cri.Attributes.Class != 2 || cri.Attributes.Tag != 0 || !cri.Attributes.IsCompound) {
		return nil, errors.New("csr: inconsistent national request profile")
	}

	return &ParsedRequest{
		Raw:             der,
		CRIRaw:          criRaw,
		Subject:         subject,
		PublicKey:       pub,
		SignatureAlgOID: cr.SignatureAlgorithm.Algorithm,
		SignatureBytes:  cr.Signature.Bytes,
		national:        national,
	}, nil
}

// Verify checks the self-signature on the parsed CSR.
func (r *ParsedRequest) Verify() error {
	if r == nil || r.PublicKey == nil || r.PublicKey.Curve == nil {
		return errors.New("csr: verify: no public key")
	}

	if err := checkSignatureProfile(r.SignatureAlgOID, r.PublicKey.Curve); err != nil {
		return err
	}
	hasher := hashData
	if r.national {
		hasher = hashNational
	}
	digest, err := hasher(r.CRIRaw, r.SignatureAlgOID)
	if err != nil {
		return errors.New("csr: verify: hash: " + err.Error())
	}

	var sig *dstu4145.Signature
	if r.national {
		var raw []byte
		var rest []byte
		rest, err = asn1.Unmarshal(r.SignatureBytes, &raw)
		if err == nil && len(rest) == 0 {
			sig, err = dstu4145.UnmarshalSignatureRaw(raw, r.PublicKey.Curve)
		} else {
			return errors.New("csr: invalid national signature wrapper")
		}
	} else {
		sig, err = dstu4145.UnmarshalSignature(r.SignatureBytes, r.PublicKey.Curve.Words)
	}
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

// buildCRI builds the DER-encoded CertificationRequestInfo.
func buildCRI(subjectDER []byte, spki subjectPublicKeyInfo) ([]byte, error) {
	cri := certificationRequestInfo{
		Version:    0,
		Subject:    asn1.RawValue{FullBytes: subjectDER},
		PublicKey:  spki,
		Attributes: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true},
	}
	return asn1.Marshal(cri)
}

// hashData hashes data using the algorithm indicated by sigAlgOID.
func hashData(data []byte, sigAlgOID asn1.ObjectIdentifier) ([]byte, error) {
	switch {
	case sigAlgOID.Equal(oid.DSTU4145WithGOST34311), sigAlgOID.Equal(oid.DSTU4145ONBWithGOST34311):
		h := gost34311.New()
		_, _ = h.Write(data)
		return h.Sum(nil), nil
	case sigAlgOID.Equal(oid.DSTU4145WithKupyna256), sigAlgOID.Equal(oid.DSTU4145ONBWithKupyna256):
		h := kupyna.New256()
		_, _ = h.Write(data)
		return h.Sum(nil), nil
	case sigAlgOID.Equal(oid.DSTU4145WithKupyna512), sigAlgOID.Equal(oid.DSTU4145ONBWithKupyna512):
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
