package cms

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

// IssuerAndSerialNumber identifies a certificate by its issuer DN and serial number.
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// AlgorithmIdentifier mirrors pkix.AlgorithmIdentifier for CMS use.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// EncapsulatedContentInfo holds the signed content.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"optional,explicit,tag:0"`
}

// SignerInfo is RFC 5652 §5.3.
// It is encoded/decoded manually to preserve SignedAttrs SET bytes verbatim.
type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue // raw DER of the SET OF Attribute (tag 0x31)
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue // raw DER of unsigned attrs (may be empty)
}

// marshalSignerInfo encodes a SignerInfo to DER manually.
func marshalSignerInfo(si SignerInfo) ([]byte, error) {
	versionDER, err := asn1.Marshal(si.Version)
	if err != nil {
		return nil, err
	}
	sidDER, err := asn1.Marshal(si.SID)
	if err != nil {
		return nil, err
	}
	digAlgDER, err := asn1.Marshal(si.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	sigAlgDER, err := asn1.Marshal(si.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	sigDER, err := asn1.Marshal(si.Signature)
	if err != nil {
		return nil, err
	}

	var inner []byte
	inner = append(inner, versionDER...)
	inner = append(inner, sidDER...)
	inner = append(inner, digAlgDER...)
	if len(si.SignedAttrs.FullBytes) > 0 {
		attrs := append([]byte(nil), si.SignedAttrs.FullBytes...)
		attrs[0] = 0xa0 // [0] IMPLICIT; the digest uses the SET tag instead.
		inner = append(inner, attrs...)
	}
	inner = append(inner, sigAlgDER...)
	inner = append(inner, sigDER...)
	if len(si.UnsignedAttrs.FullBytes) > 0 {
		inner = append(inner, si.UnsignedAttrs.FullBytes...)
	}
	return marshalSEQ(inner), nil
}

// parseSignerInfos decodes a SET OF SignerInfo from raw DER bytes.
// Each SignerInfo is a SEQUENCE; the outer SET has tag 0x31.
func parseSignerInfos(setDER []byte) ([]SignerInfo, error) {
	// Unwrap the SET OF
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(setDER, &outer); err != nil {
		return nil, errors.New("cms: parse SignerInfos SET: " + err.Error())
	}
	inner := outer.Bytes
	var infos []SignerInfo
	for len(inner) > 0 {
		var seq asn1.RawValue
		rest, err := asn1.Unmarshal(inner, &seq)
		if err != nil {
			return nil, errors.New("cms: parse SignerInfo seq: " + err.Error())
		}
		inner = rest
		si, err := parseOneSignerInfo(seq.Bytes)
		if err != nil {
			return nil, err
		}
		infos = append(infos, si)
	}
	return infos, nil
}

// parseOneSignerInfo parses the inner bytes of one SignerInfo SEQUENCE.
func parseOneSignerInfo(data []byte) (SignerInfo, error) {
	var si SignerInfo

	// Version INTEGER
	rest, err := asn1.Unmarshal(data, &si.Version)
	if err != nil {
		return si, errors.New("cms: SignerInfo version: " + err.Error())
	}

	// SID IssuerAndSerialNumber — parse manually to avoid RawValue eating too much
	{
		var sidSeq asn1.RawValue
		var r []byte
		r, err = asn1.Unmarshal(rest, &sidSeq)
		if err != nil {
			return si, errors.New("cms: SignerInfo SID seq: " + err.Error())
		}
		rest = r
		// Parse Issuer (RawValue = full TLV)
		var issuerRaw asn1.RawValue
		sidRest, err2 := asn1.Unmarshal(sidSeq.Bytes, &issuerRaw)
		if err2 != nil {
			return si, errors.New("cms: SignerInfo SID issuer: " + err2.Error())
		}
		si.SID.Issuer = asn1.RawValue{FullBytes: sidSeq.Bytes[:len(sidSeq.Bytes)-len(sidRest)]}
		// Parse SerialNumber (big.Int)
		if _, err2 = asn1.Unmarshal(sidRest, &si.SID.SerialNumber); err2 != nil {
			return si, errors.New("cms: SignerInfo SID serial: " + err2.Error())
		}
	}

	// DigestAlgorithm AlgorithmIdentifier
	rest, err = asn1.Unmarshal(rest, &si.DigestAlgorithm)
	if err != nil {
		return si, errors.New("cms: SignerInfo digestAlgorithm: " + err.Error())
	}

	// SignedAttrs: [0] IMPLICIT SET OF (tag 0xa0, per RFC 5652) or bare SET (0x31).
	if len(rest) > 0 && (rest[0] == 0xa0 || rest[0] == 0x31) {
		var raw asn1.RawValue
		var r []byte
		r, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return si, errors.New("cms: SignerInfo signedAttrs: " + err.Error())
		}
		si.SignedAttrs = asn1.RawValue{FullBytes: rest[:len(rest)-len(r)]}
		rest = r
	}

	// SignatureAlgorithm AlgorithmIdentifier
	rest, err = asn1.Unmarshal(rest, &si.SignatureAlgorithm)
	if err != nil {
		return si, errors.New("cms: SignerInfo signatureAlgorithm: " + err.Error())
	}

	// Signature OCTET STRING
	rest, err = asn1.Unmarshal(rest, &si.Signature)
	if err != nil {
		return si, errors.New("cms: SignerInfo signature: " + err.Error())
	}

	// UnsignedAttrs: if next tag is 0xa1 (implicit [1]), consume it
	if len(rest) > 0 && rest[0] == 0xa1 {
		var raw asn1.RawValue
		var r []byte
		r, err = asn1.Unmarshal(rest, &raw)
		if err == nil {
			si.UnsignedAttrs = asn1.RawValue{FullBytes: rest[:len(rest)-len(r)]}
			rest = r
		}
	}
	if len(rest) != 0 {
		return si, errors.New("cms: trailing SignerInfo fields")
	}
	return si, nil
}

// parsedSignedData holds the decoded fields of a SignedData.
type parsedSignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier
	EContentType     asn1.ObjectIdentifier
	EContent         []byte // nil if detached
	CertBytes        []byte // raw cert bytes inside [0] context tag
	SignerInfos      []SignerInfo
}

// marshalSignedData manually encodes a SignedData SEQUENCE.
// certDERs contains raw DER of certificates to embed in [0] IMPLICIT.
func marshalSignedData(
	version int,
	digestAlgOID asn1.ObjectIdentifier,
	eci EncapsulatedContentInfo,
	signerInfos []SignerInfo,
	certDERs ...[]byte,
) ([]byte, error) {
	versionDER, err := asn1.Marshal(version)
	if err != nil {
		return nil, err
	}

	// DigestAlgorithms SET { AlgorithmIdentifier }
	algDER, err := asn1.Marshal(digestAlgOID)
	if err != nil {
		return nil, err
	}
	algIDDER := marshalSEQ(algDER) // SEQUENCE { OID }
	digestAlgSetDER := marshalSETOF(algIDDER)

	// EncapsulatedContentInfo
	eciDER, err := marshalECI(eci)
	if err != nil {
		return nil, err
	}

	// SignerInfos SET OF
	var siBytes []byte
	var sib []byte
	for _, si := range signerInfos {
		sib, err = marshalSignerInfo(si)
		if err != nil {
			return nil, err
		}
		siBytes = append(siBytes, sib...)
	}
	signerInfosSetDER := marshalSETOF(siBytes)

	inner := versionDER
	inner = append(inner, digestAlgSetDER...)
	inner = append(inner, eciDER...)

	// Optional [0] IMPLICIT SEQUENCE OF Certificate
	if len(certDERs) > 0 {
		var certBytes []byte
		for _, der := range certDERs {
			certBytes = append(certBytes, der...)
		}
		inner = append(inner, tlv(0xa0, certBytes)...)
	}

	inner = append(inner, signerInfosSetDER...)
	return marshalSEQ(inner), nil
}

// marshalECI encodes an EncapsulatedContentInfo.
func marshalECI(eci EncapsulatedContentInfo) ([]byte, error) {
	oidDER, err := asn1.Marshal(eci.EContentType)
	if err != nil {
		return nil, err
	}
	inner := oidDER
	if eci.EContent != nil {
		// OCTET STRING wrapped in EXPLICIT [0]
		var contentDER []byte
		contentDER, err = asn1.Marshal(eci.EContent)
		if err != nil {
			return nil, err
		}
		inner = append(inner, marshalEXPLICIT(0, contentDER)...)
	}
	return marshalSEQ(inner), nil
}

// parseSignedDataBytes manually parses a SignedData SEQUENCE (including its outer tag).
func parseSignedDataBytes(data []byte) (*parsedSignedData, error) {
	// Unwrap the outer SEQUENCE tag to get the inner content bytes.
	var outer asn1.RawValue
	var err error
	_, err = asn1.Unmarshal(data, &outer)
	if err != nil {
		return nil, errors.New("cms: parse SignedData outer: " + err.Error())
	}
	data = outer.Bytes

	sd := &parsedSignedData{}

	// Version
	rest, err := asn1.Unmarshal(data, &sd.Version)
	if err != nil {
		return nil, errors.New("cms: parse SignedData version: " + err.Error())
	}

	// DigestAlgorithms SET
	var digestAlgsRaw asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &digestAlgsRaw)
	if err != nil {
		return nil, errors.New("cms: parse DigestAlgorithms: " + err.Error())
	}
	// Parse the first AlgorithmIdentifier from the SET (simplified)
	if len(digestAlgsRaw.Bytes) > 0 {
		var algID AlgorithmIdentifier
		_, err = asn1.Unmarshal(digestAlgsRaw.Bytes, &algID)
		if err == nil {
			sd.DigestAlgorithms = []AlgorithmIdentifier{algID}
		}
	}

	// EncapsulatedContentInfo
	rest, err = parseECI(rest, sd)
	if err != nil {
		return nil, err
	}

	// Optional [0] Certificates
	if len(rest) > 0 && rest[0] == 0xa0 {
		var certsRaw asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &certsRaw)
		if err != nil {
			return nil, errors.New("cms: parse Certificates: " + err.Error())
		}
		sd.CertBytes = certsRaw.Bytes
	}

	// Optional [1] CRLs
	if len(rest) > 0 && rest[0] == 0xa1 {
		var crlsRaw asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &crlsRaw)
		if err != nil {
			return nil, errors.New("cms: parse CRLs: " + err.Error())
		}
	}

	// SignerInfos SET OF
	if len(rest) == 0 {
		return sd, nil
	}
	sd.SignerInfos, err = parseSignerInfos(rest)
	if err != nil {
		return nil, err
	}

	return sd, nil
}

// parseECI parses an EncapsulatedContentInfo from rest, updating sd, and returns remaining bytes.
func parseECI(rest []byte, sd *parsedSignedData) ([]byte, error) {
	var eciSeq asn1.RawValue
	remaining, err := asn1.Unmarshal(rest, &eciSeq)
	if err != nil {
		return nil, errors.New("cms: parse ECI: " + err.Error())
	}
	eciInner := eciSeq.Bytes

	// EContentType OID
	var r []byte
	r, err = asn1.Unmarshal(eciInner, &sd.EContentType)
	if err != nil {
		return nil, errors.New("cms: parse EContentType: " + err.Error())
	}

	// Optional EXPLICIT [0] { OCTET STRING content }
	if len(r) > 0 && r[0] == 0xa0 {
		var explicitWrapper asn1.RawValue
		_, err = asn1.Unmarshal(r, &explicitWrapper)
		if err == nil {
			var content []byte
			if _, err2 := asn1.Unmarshal(explicitWrapper.Bytes, &content); err2 == nil {
				sd.EContent = content
			}
		}
	}

	return remaining, nil
}

// ContentInfo is the CMS top-level wrapper.
// Content holds the raw DER of the inner type (e.g. SignedData SEQUENCE),
// wrapped in EXPLICIT [0] on the wire. We handle this manually.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

// SignOptions controls SignedData creation.
type SignOptions struct {
	// ContentTimestamp is an already authenticated RFC3161 token over content.
	// Caller verification is required because tsp depends on this CMS package.
	ContentTimestamp []byte
	Detached         bool                  // omit content from SignedData
	ContentType      asn1.ObjectIdentifier // default: OIDData
	DigestAlgorithm  asn1.ObjectIdentifier // default: supported certificate public-key profile
}

// SignedMessage is the result of parsing a SignedData.
type SignedMessage struct {
	Content      []byte // nil if detached
	Signers      []SignerResult
	Certificates []*cert.Certificate
	rawSigners   []SignerInfo
	contentType  asn1.ObjectIdentifier
}

// SignerResult is the verification result for one signer.
type SignerResult struct {
	Certificate *cert.Certificate
	SigningTime time.Time
	Valid       bool
	Error       error
	sid         IssuerAndSerialNumber // unexported; used by ResolveCertificates
}

// Sign creates a CMS SignedData for content using the given private key and certificate.
// Returns DER-encoded ContentInfo wrapping SignedData.
func Sign(content []byte, key *dstu4145.PrivateKey, signerCert *cert.Certificate, opts SignOptions) ([]byte, error) {
	if opts.ContentType == nil {
		opts.ContentType = OIDData
	}

	if key == nil || signerCert == nil {
		return nil, errors.New("cms: signing key and certificate are required")
	}
	if err := cert.VerifyCertPKMatch(signerCert, key); err != nil {
		return nil, err
	}
	digestAlgOID := opts.DigestAlgorithm
	if len(digestAlgOID) == 0 {
		switch {
		case len(signerCert.PublicKeyAlgorithm) == 0:
			digestAlgOID = oid.Kupyna256
		case signerCert.PublicKeyAlgorithm.Equal(oid.DSTU4145WithGOST34311), oid.IsCurveOID(signerCert.PublicKeyAlgorithm):
			digestAlgOID = oid.GOST34311
		case signerCert.PublicKeyAlgorithm.Equal(oid.DSTU4145WithKupyna256):
			digestAlgOID = oid.Kupyna256
		case signerCert.PublicKeyAlgorithm.Equal(oid.DSTU4145WithKupyna512):
			digestAlgOID = oid.Kupyna512
		default:
			return nil, errors.New("cms: unsupported signing public-key algorithm")
		}
	}
	if err := cert.CheckSigningUsage(signerCert); err != nil {
		return nil, err
	}
	sigAlgOID, err := signatureAlgorithmForDigest(digestAlgOID)
	if err != nil {
		return nil, err
	}
	// 1. Compute the content digest using the selected profile.
	h := newHashForOID(digestAlgOID)
	h.Write(content)
	digest := h.Sum(nil)

	// 2. Build signed attributes
	now := time.Now().UTC().Truncate(time.Second)
	attrs, err := BuildSignedAttrs(opts.ContentType, digest, now)
	if err != nil {
		return nil, err
	}
	certificateAttribute, err := signingCertificateAttribute(signerCert, digestAlgOID)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, certificateAttribute)
	if len(opts.ContentTimestamp) > 0 {
		if len(opts.ContentTimestamp) > 4<<20 {
			return nil, errors.New("cms: content timestamp exceeds size limit")
		}
		token, err := ParseSigned(opts.ContentTimestamp)
		if err != nil || !token.ContentType().Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}) {
			return nil, errors.New("cms: content timestamp token is required")
		}
		attrs = append(attrs, Attribute{Type: OIDContentTimestamp, Values: asn1.RawValue{FullBytes: marshalSETOF(opts.ContentTimestamp)}})
	}

	// 3. DER-encode signed attrs as SET OF (this is what gets signed)
	signedAttrsDER, err := MarshalSignedAttrs(attrs)
	if err != nil {
		return nil, err
	}

	// 4. Hash the signed attrs and sign
	h2 := newHashForOID(digestAlgOID)
	h2.Write(signedAttrsDER)
	attrDigest := h2.Sum(nil)

	if isLEHashOID(digestAlgOID) {
		attrDigest = reverseBytes(attrDigest)
	}
	sig, err := dstu4145.Sign(rand.Reader, key, attrDigest)
	if err != nil {
		return nil, errors.New("cms: Sign: " + err.Error())
	}

	sigDER, err := dstu4145.MarshalSignatureRaw(sig, key.Curve)
	if err != nil {
		return nil, err
	}
	si := SignerInfo{
		Version: 1,
		SID: IssuerAndSerialNumber{
			Issuer:       signerCert.Issuer,
			SerialNumber: signerCert.SerialNumber,
		},
		DigestAlgorithm:    AlgorithmIdentifier{Algorithm: digestAlgOID},
		SignedAttrs:        asn1.RawValue{FullBytes: signedAttrsDER},
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: sigAlgOID},
		Signature:          sigDER,
	}

	// 7. Build EncapContentInfo
	eci := EncapsulatedContentInfo{EContentType: opts.ContentType}
	if !opts.Detached {
		eci.EContent = append([]byte{}, content...)
	}

	sdDER, err := marshalSignedData(1, digestAlgOID, eci, []SignerInfo{si}, signerCert.Raw)
	if err != nil {
		return nil, errors.New("cms: marshal SignedData: " + err.Error())
	}

	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{FullBytes: marshalEXPLICIT(0, sdDER)},
	}

	// Marshal as SEQUENCE { OID, [0] EXPLICIT sdDER }
	oidDER, err := asn1.Marshal(ci.ContentType)
	if err != nil {
		return nil, err
	}
	return marshalSEQ(slices.Concat(oidDER, ci.Content.FullBytes)), nil
}

// ParseSigned parses a DER-encoded ContentInfo/SignedData.
// For detached signatures, content will be nil; call VerifySigned with the detached content.
func ParseSigned(der []byte) (*SignedMessage, error) {
	sdBytes, err := parseContentInfo(der, OIDSignedData)
	if err != nil {
		return nil, err
	}

	sd, err := parseSignedDataBytes(sdBytes)
	if err != nil {
		return nil, errors.New("cms: parse SignedData: " + err.Error())
	}

	msg := &SignedMessage{rawSigners: sd.SignerInfos, contentType: sd.EContentType}
	if sd.EContent != nil {
		msg.Content = sd.EContent
	}

	if len(sd.CertBytes) > 0 {
		var certs []*cert.Certificate
		certs, err = cert.ParseCertificates(sd.CertBytes)
		if err == nil {
			msg.Certificates = certs
		}
	}

	for _, si := range sd.SignerInfos {
		sr := SignerResult{sid: si.SID}
		for _, c := range msg.Certificates {
			if matchesSID(c, si.SID) {
				sr.Certificate = c
				break
			}
		}
		sr.SigningTime = extractSigningTime(si.SignedAttrs.FullBytes)
		msg.Signers = append(msg.Signers, sr)
	}

	return msg, nil
}

// ResolveCertificates re-runs SID matching for any signer whose Certificate is still nil.
// Call this after adding extra certificates to msg.Certificates.
func ResolveCertificates(msg *SignedMessage) {
	for i := range msg.Signers {
		if msg.Signers[i].Certificate != nil {
			continue
		}
		sid := msg.Signers[i].sid
		for _, c := range msg.Certificates {
			if matchesSID(c, sid) {
				msg.Signers[i].Certificate = c
				break
			}
		}
	}
}

// matchesSID checks if a certificate matches an IssuerAndSerialNumber.
func matchesSID(c *cert.Certificate, sid IssuerAndSerialNumber) bool {
	if c == nil || c.SerialNumber == nil || sid.SerialNumber == nil {
		return false
	}
	// Compare serial numbers directly
	if c.SerialNumber.Cmp(sid.SerialNumber) != 0 {
		return false
	}
	// Compare issuer: prefer FullBytes, fall back to Bytes
	cIssuer := c.Issuer.FullBytes
	if len(cIssuer) == 0 {
		cIssuer = c.Issuer.Bytes
	}
	sidIssuer := sid.Issuer.FullBytes
	if len(sidIssuer) == 0 {
		sidIssuer = sid.Issuer.Bytes
	}
	if len(cIssuer) > 0 && len(sidIssuer) > 0 {
		return bytesEqual(cIssuer, sidIssuer)
	}
	return true
}

// extractSigningTime returns the signingTime from raw SET OF Attribute DER bytes.
func extractSigningTime(setDER []byte) time.Time {
	if len(setDER) == 0 {
		return time.Time{}
	}
	attrs, err := parseRawAttributes(setDER)
	if err != nil {
		return time.Time{}
	}
	for _, a := range attrs {
		if a.Type.Equal(OIDSigningTime) {
			var t time.Time
			// a.Values.FullBytes is SET { time }; unwrap the SET
			var inner asn1.RawValue
			var parseErr error
			_, parseErr = asn1.Unmarshal(a.Values.FullBytes, &inner)
			if parseErr != nil {
				continue
			}
			_, parseErr = asn1.Unmarshal(inner.Bytes, &t)
			if parseErr != nil {
				continue
			}
			return t
		}
	}
	return time.Time{}
}

// extractMessageDigest extracts the message-digest octet string from signed attrs DER.
func extractMessageDigest(setDER []byte) ([]byte, error) {
	attrs, err := parseRawAttributes(setDER)
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		if a.Type.Equal(OIDMessageDigest) {
			var inner asn1.RawValue
			_, err = asn1.Unmarshal(a.Values.FullBytes, &inner)
			if err != nil {
				return nil, errors.New("cms: parse messageDigest SET: " + err.Error())
			}
			var digest []byte
			_, err = asn1.Unmarshal(inner.Bytes, &digest)
			if err != nil {
				return nil, errors.New("cms: parse messageDigest value: " + err.Error())
			}
			return digest, nil
		}
	}
	return nil, errors.New("cms: messageDigest attribute not found")
}

// parseRawAttributes parses a SET OF Attribute from DER bytes.
// The outer tag is expected to be 0x31 (SET) or 0xa0 (implicit [0]).
func parseRawAttributes(setDER []byte) ([]rawAttribute, error) {
	if len(setDER) == 0 {
		return nil, nil
	}
	// The bytes may have an outer SET (0x31) or context [0] (0xa0) tag.
	// Strip the outer wrapper to get the inner concatenated SEQUENCE list.
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(setDER, &outer)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("cms: parse attrs outer: " + func() string {
			if err != nil {
				return err.Error()
			}
			return "trailing bytes"
		}())
	}
	if !outer.IsCompound || !(outer.Class == 0 && outer.Tag == 17 || outer.Class == 2 && (outer.Tag == 0 || outer.Tag == 1)) {
		return nil, errors.New("cms: malformed attribute set")
	}
	inner := outer.Bytes

	var attrs []rawAttribute
	var seq asn1.RawValue
	var loopErr error
	var valRest []byte
	var loopOID asn1.ObjectIdentifier
	for len(inner) > 0 {
		inner, loopErr = asn1.Unmarshal(inner, &seq)
		if loopErr != nil {
			return nil, loopErr
		}
		if seq.Class != 0 || seq.Tag != 16 || !seq.IsCompound {
			return nil, errors.New("cms: malformed attribute sequence")
		}
		// seq.Bytes = OID || SET
		valRest, loopErr = asn1.Unmarshal(seq.Bytes, &loopOID)
		if loopErr != nil {
			return nil, loopErr
		}
		var values asn1.RawValue
		if rest, err := asn1.Unmarshal(valRest, &values); err != nil || len(rest) != 0 || values.Class != 0 || values.Tag != 17 || !values.IsCompound || len(values.Bytes) == 0 {
			return nil, errors.New("cms: malformed attribute values")
		}
		// valRest = SET { value }
		attrs = append(attrs, rawAttribute{
			Type:   loopOID,
			Values: asn1.RawValue{FullBytes: valRest},
		})
	}
	return attrs, nil
}

type rawAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// parseContentInfo parses a manually-encoded ContentInfo SEQUENCE and returns
// the expected OID check error and the inner content bytes (after unwrapping [0] EXPLICIT).
func parseContentInfo(der []byte, expectedOID asn1.ObjectIdentifier) ([]byte, error) {
	// Outer SEQUENCE
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, errors.New("cms: parse ContentInfo: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, errors.New("cms: trailing bytes after ContentInfo")
	}

	inner := outer.Bytes

	// OID
	var oid asn1.ObjectIdentifier
	var rest2 []byte
	rest2, err = asn1.Unmarshal(inner, &oid)
	if err != nil {
		return nil, errors.New("cms: parse ContentInfo OID: " + err.Error())
	}
	if expectedOID != nil && !oid.Equal(expectedOID) {
		return nil, errors.New("cms: unexpected ContentInfo OID: " + oid.String())
	}

	// rest2 should be [0] EXPLICIT { content }
	if len(rest2) == 0 {
		return nil, errors.New("cms: ContentInfo has no content")
	}
	var contentWrapper asn1.RawValue
	_, err = asn1.Unmarshal(rest2, &contentWrapper)
	if err != nil {
		return rest2, nil //nolint:nilerr // fallback: some CMS implementations omit the [0] EXPLICIT wrapper; treat bytes as raw content
	}
	// contentWrapper.Bytes is the actual content DER
	return contentWrapper.Bytes, nil
}

// marshalEXPLICIT wraps content in an EXPLICIT context tag.
func marshalEXPLICIT(tag int, content []byte) []byte {
	return tlv(byte(0xa0|tag), content)
}

// signedAttrsForHashing returns a copy of signedAttrs bytes with the outer tag
// rewritten to SET (0x31) if it is [0] IMPLICIT (0xa0), as required by RFC 5652 §5.4.
func signedAttrsForHashing(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if b[0] == 0xa0 {
		out := make([]byte, len(b))
		copy(out, b)
		out[0] = 0x31
		return out
	}
	return b
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
