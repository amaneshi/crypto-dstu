package cms

import (
	"bytes"
	"encoding/asn1"
	"errors"
)

// ContentType returns the encapsulated content type from the original CMS.
func (m *SignedMessage) ContentType() asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier(nil), m.contentType...)
}

// SignatureBytes returns a copy of the signer's signature value octets.
func (m *SignedMessage) SignatureBytes(index int) ([]byte, error) {
	if index < 0 || index >= len(m.rawSigners) {
		return nil, errors.New("cms: invalid signer index")
	}
	return bytes.Clone(m.rawSigners[index].Signature), nil
}

// HasSigningCertificate reports whether a signer carries an ESS certificate binding.
// VerifySigned must also succeed to authenticate that binding.
func (m *SignedMessage) HasSigningCertificate(index int) bool {
	if index < 0 || index >= len(m.rawSigners) {
		return false
	}
	attrs, err := parseRawAttributes(m.rawSigners[index].SignedAttrs.FullBytes)
	if err != nil {
		return false
	}
	for _, a := range attrs {
		if a.Type.Equal(OIDSigningCertificate) || a.Type.Equal(OIDSigningCertificateV2) {
			return true
		}
	}
	return false
}

// SignatureTimestampTokens extracts bounded, single-attribute signature timestamp
// values. The returned tokens are untrusted until a timestamp verifier checks them.
func (m *SignedMessage) SignatureTimestampTokens(index int) ([][]byte, error) {
	if index < 0 || index >= len(m.rawSigners) {
		return nil, errors.New("cms: invalid signer index")
	}
	attrs, err := parseRawAttributes(m.rawSigners[index].UnsignedAttrs.FullBytes)
	if err != nil {
		return nil, err
	}
	var tokens [][]byte
	seen := false
	for _, a := range attrs {
		if !a.Type.Equal(OIDTimestampToken) {
			continue
		}
		if seen {
			return nil, errors.New("cms: duplicate signature timestamp attribute")
		}
		seen = true
		var set asn1.RawValue
		if rest, err := asn1.Unmarshal(a.Values.FullBytes, &set); err != nil || len(rest) != 0 || set.Class != 0 || set.Tag != 17 || !set.IsCompound {
			return nil, errors.New("cms: malformed timestamp values")
		}
		remaining := set.Bytes
		if len(remaining) == 0 {
			return nil, errors.New("cms: empty signature timestamp attribute")
		}
		for len(remaining) > 0 {
			var token asn1.RawValue
			var err error
			remaining, err = asn1.Unmarshal(remaining, &token)
			if err != nil || token.Class != 0 || token.Tag != 16 || !token.IsCompound || len(tokens) >= 16 {
				return nil, errors.New("cms: malformed or excessive timestamp tokens")
			}
			tokens = append(tokens, bytes.Clone(token.FullBytes))
		}
	}
	return tokens, nil
}

// AttachSignatureTimestamp appends an already authenticated token to freshly
// generated single-signer SignedData. It preserves all signed attribute bytes.
// Timestamp authentication belongs to the caller; this package cannot import tsp.
func AttachSignatureTimestamp(document, token []byte) ([]byte, error) {
	if len(token) == 0 || len(token) > 4<<20 {
		return nil, errors.New("cms: invalid timestamp token size")
	}
	parsedToken, err := ParseSigned(token)
	if err != nil {
		return nil, err
	}
	if !parsedToken.ContentType().Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}) {
		return nil, errors.New("cms: timestamp token content type is required")
	}
	inner, err := parseContentInfo(document, OIDSignedData)
	if err != nil {
		return nil, err
	}
	sd, err := parseSignedDataBytes(inner)
	if err != nil {
		return nil, err
	}
	if len(sd.SignerInfos) != 1 || len(sd.DigestAlgorithms) != 1 {
		return nil, errors.New("cms: timestamp writer requires fresh single-signer SignedData")
	}
	signer := &sd.SignerInfos[0]
	existing, err := parseRawAttributes(signer.UnsignedAttrs.FullBytes)
	if err != nil {
		return nil, err
	}
	var attrs []Attribute
	for _, a := range existing {
		if a.Type.Equal(OIDTimestampToken) {
			return nil, errors.New("cms: signature timestamp already exists")
		}
		attrs = append(attrs, Attribute{Type: a.Type, Values: a.Values})
	}
	attrs = append(attrs, Attribute{Type: OIDTimestampToken, Values: asn1.RawValue{FullBytes: marshalSETOF(token)}})
	unsigned, err := MarshalSignedAttrs(attrs)
	if err != nil {
		return nil, err
	}
	unsigned[0] = 0xa1
	signer.UnsignedAttrs = asn1.RawValue{FullBytes: unsigned}
	encoded, err := marshalSignedData(sd.Version, sd.DigestAlgorithms[0].Algorithm, EncapsulatedContentInfo{EContentType: sd.EContentType, EContent: sd.EContent}, sd.SignerInfos, sd.CertBytes)
	if err != nil {
		return nil, err
	}
	typ, err := asn1.Marshal(OIDSignedData)
	if err != nil {
		return nil, err
	}
	return marshalSEQ(append(typ, marshalEXPLICIT(0, encoded)...)), nil
}
