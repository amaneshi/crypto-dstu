package cms

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
)

// VerifySigned verifies every signature, including the content digest. A nil root
// pool explicitly requests mathematical verification only, not identity trust.
func VerifySigned(msg *SignedMessage, content []byte, roots []*cert.Certificate) error {
	if msg == nil || len(msg.Signers) == 0 || len(msg.rawSigners) != len(msg.Signers) {
		return errors.New("cms: no original signer information")
	}
	if content == nil {
		content = msg.Content
	}
	// Reset previous results even when re-verification fails before reaching a signer.
	for i := range msg.Signers {
		msg.Signers[i].Valid = false
		msg.Signers[i].Error = nil
	}
	if msg.Content != nil && !bytes.Equal(content, msg.Content) {
		return errors.New("cms: supplied content differs from attached content")
	}
	if content == nil {
		return errors.New("cms: detached content is required")
	}
	msg.Certificates = append(msg.Certificates, roots...)
	ResolveCertificates(msg)
	var failures []error
	for i, si := range msg.rawSigners {
		sr := &msg.Signers[i]
		sr.Error = verifySigner(si, sr.Certificate, content, msg.contentType, roots, msg.Certificates)
		sr.Valid = sr.Error == nil
		if sr.Error != nil {
			failures = append(failures, fmt.Errorf("cms: signer %d: %w", i, sr.Error))
		}
	}
	return errors.Join(failures...)
}

// VerifySignedRaw parses and verifies SignedData. Roots are explicit trust
// anchors, never merely a source of signer certificates. Nil skips trust only.
func VerifySignedRaw(der, content []byte, roots []*cert.Certificate) (*SignedMessage, error) {
	msg, err := ParseSigned(der)
	if err != nil {
		return nil, err
	}
	return msg, VerifySigned(msg, content, roots)
}

func verifySigner(si SignerInfo, c *cert.Certificate, content []byte, contentType asn1.ObjectIdentifier, roots, intermediates []*cert.Certificate) error {
	if c == nil || c.PublicKey == nil || c.PublicKey.Curve == nil {
		return errors.New("signer certificate or public key not found")
	}
	if roots != nil {
		if err := cert.VerifyCertChainWithIntermediates(c, roots, intermediates); err != nil {
			return fmt.Errorf("certificate trust: %w", err)
		}
	}
	if err := cert.CheckSigningUsage(c); err != nil {
		return err
	}
	expected, err := signatureAlgorithmForCurve(si.DigestAlgorithm.Algorithm, c.PublicKey.Curve)
	if err != nil {
		return err
	}
	if !si.SignatureAlgorithm.Algorithm.Equal(expected) {
		return errors.New("unsupported signature algorithm or inconsistent digest")
	}
	signed := content
	if len(si.SignedAttrs.FullBytes) == 0 && !contentType.Equal(OIDData) {
		return errors.New("signed attributes are required for non-data content")
	}
	if len(si.SignedAttrs.FullBytes) > 0 {
		attrs, err := parseRawAttributes(si.SignedAttrs.FullBytes)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		var claimed []byte
		var attrType asn1.ObjectIdentifier
		for _, a := range attrs {
			key := a.Type.String()
			if seen[key] {
				return errors.New("duplicate signed attribute")
			}
			seen[key] = true
			var set asn1.RawValue
			rest, parseErr := asn1.Unmarshal(a.Values.FullBytes, &set)
			if parseErr != nil || len(rest) != 0 || set.Tag != 17 || set.Class != 0 {
				return errors.New("invalid signed attribute values")
			}
			if a.Type.Equal(OIDMessageDigest) {
				rest, parseErr = asn1.Unmarshal(set.Bytes, &claimed)
			} else if a.Type.Equal(OIDContentType) {
				rest, parseErr = asn1.Unmarshal(set.Bytes, &attrType)
			} else if a.Type.Equal(OIDSigningCertificate) {
				if err := verifySigningCertificateV1(set.Bytes, c); err != nil {
					return err
				}
				continue
			} else if a.Type.Equal(OIDSigningCertificateV2) {
				if err := verifySigningCertificateAttribute(set.Bytes, c); err != nil {
					return err
				}
				continue
			} else {
				continue
			}
			if parseErr != nil || len(rest) != 0 {
				return errors.New("signed attribute must have exactly one value")
			}
		}
		if !seen[OIDMessageDigest.String()] || !seen[OIDContentType.String()] || !attrType.Equal(contentType) {
			return errors.New("missing or mismatched signed content type/digest")
		}
		h := newHashForOID(si.DigestAlgorithm.Algorithm)
		h.Write(content)
		if !bytes.Equal(h.Sum(nil), claimed) {
			return errors.New("message digest mismatch")
		}
		signed = signedAttrsForHashing(si.SignedAttrs.FullBytes)
	}
	// SignedAttrs is optional: absent attributes mean a direct content signature,
	// not an exemption from verification.
	h := newHashForOID(si.DigestAlgorithm.Algorithm)
	h.Write(signed)
	digest := h.Sum(nil)
	if isLEHashOID(si.DigestAlgorithm.Algorithm) {
		digest = reverseBytes(digest)
	}
	sig, err := unmarshalSignatureCMS(si.Signature, c.PublicKey.Curve)
	if err != nil {
		return err
	}
	if !dstu4145.Verify(c.PublicKey, digest, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

func signatureAlgorithmForCurve(digest asn1.ObjectIdentifier, curve *ec.Curve) (asn1.ObjectIdentifier, error) {
	if curve.IsONB() {
		switch {
		case digest.Equal(oid.GOST34311):
			return oid.DSTU4145ONBWithGOST34311, nil
		case digest.Equal(oid.Kupyna256):
			return oid.DSTU4145ONBWithKupyna256, nil
		case digest.Equal(oid.Kupyna512):
			return oid.DSTU4145ONBWithKupyna512, nil
		default:
			return nil, errors.New("cms: unsupported ONB signature profile")
		}
	}
	return signatureAlgorithmForDigest(digest)
}

func signatureAlgorithmForDigest(digest asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	switch {
	case digest.Equal(oid.GOST34311):
		return oid.DSTU4145WithGOST34311, nil
	case digest.Equal(oid.Kupyna256):
		return oid.DSTU4145WithKupyna256, nil
	case digest.Equal(oid.Kupyna512):
		return oid.DSTU4145WithKupyna512, nil
	default:
		return nil, fmt.Errorf("cms: unsupported digest algorithm %s", digest)
	}
}
