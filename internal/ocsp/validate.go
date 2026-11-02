package ocsp

import (
	"bytes"
	"crypto/sha1"
	"encoding/asn1"
	"errors"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/oid"
)

var (
	ErrNoStatus         = errors.New("ocsp: no matching certificate status")
	ErrRevoked          = errors.New("ocsp: certificate is revoked")
	ErrUnknown          = errors.New("ocsp: certificate status is unknown")
	oidOCSPSigning      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidOCSPNoCheck      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
	oidExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

func (r *Response) responderMatches(c *cert.Certificate) bool {
	if r == nil || c == nil || r.responderID.Class != 2 || !r.responderID.IsCompound {
		return false
	}
	switch r.responderID.Tag {
	case 1:
		return bytes.Equal(r.responderID.Bytes, c.Subject.FullBytes)
	case 2:
		var keyHash []byte
		if rest, err := asn1.Unmarshal(r.responderID.Bytes, &keyHash); err != nil || len(rest) != 0 || len(c.SubjectPublicKeyBytes) == 0 {
			return false
		}
		h := sha1.Sum(c.SubjectPublicKeyBytes) // RFC 6960 ResponderID uses SHA-1 even for DSTU signatures.
		return bytes.Equal(h[:], keyHash)
	}
	return false
}

func authorizedDelegate(c, issuer *cert.Certificate, now time.Time, crls [][]byte, crlAge, skew time.Duration) bool {
	if c == nil || issuer == nil || !bytes.Equal(c.Issuer.FullBytes, issuer.Subject.FullBytes) || now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return false
	}
	if cert.VerifyCertAt(c, issuer, now) != nil || cert.CheckSigningUsage(c) != nil {
		return false
	}
	var eku, noCheck bool
	seen := map[string]bool{}
	for _, ext := range c.Extensions {
		if seen[ext.Id.String()] {
			return false
		}
		seen[ext.Id.String()] = true
		switch {
		case ext.Id.Equal(oidExtendedKeyUsage):
			var uses []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(ext.Value, &uses); err != nil || len(rest) != 0 {
				return false
			}
			for _, use := range uses {
				eku = eku || use.Equal(oidOCSPSigning)
			}
		case ext.Id.Equal(oidOCSPNoCheck):
			if !bytes.Equal(ext.Value, []byte{5, 0}) || ext.Critical {
				return false
			}
			noCheck = true
		case ext.Id.Equal(oid.OIDExtBasicConstraints):
			var constraints struct {
				CA   bool `asn1:"optional"`
				Path int  `asn1:"optional,default:-1"`
			}
			if rest, err := asn1.Unmarshal(ext.Value, &constraints); err != nil || len(rest) != 0 {
				return false
			}
		default:
			if ext.Critical && !ext.Id.Equal(oid.OIDExtKeyUsage) && !ext.Id.Equal(oid.OIDExtBasicConstraints) {
				return false
			}
		}
	}
	if !eku {
		return false
	}
	if noCheck {
		return true
	}
	valid := false
	for _, der := range crls {
		err := checkResponderCRL(der, c, issuer, now, crlAge, skew)
		if errors.Is(err, errUnrelatedCRL) {
			continue
		}
		if err != nil {
			return false
		}
		valid = true
	}
	return valid
}

func (r *Response) verifyAuthorized(issuer *cert.Certificate, now time.Time, crls [][]byte, crlAge, skew time.Duration) error {
	if r.Verify(issuer) == nil {
		return nil
	}
	for _, responder := range r.Certificates {
		if r.responderMatches(responder) && authorizedDelegate(responder, issuer, now, crls, crlAge, skew) && cert.VerifyDataSignature(r.tbsResponseDataRaw, r.sigBytes, r.sigAlgOID, responder.PublicKey) == nil {
			return nil
		}
	}
	return errors.New("ocsp: no authorized responder with a valid signature")
}

func (r *Response) find(subject, issuer *cert.Certificate) (*SingleResponse, error) {
	if r == nil || r.Status != 0 || subject == nil || subject.SerialNumber == nil {
		return nil, ErrNoStatus
	}
	var found *SingleResponse
	for i := range r.Responses {
		single := &r.Responses[i]
		id := &single.CertID
		if id.SerialNumber == nil || id.SerialNumber.Cmp(subject.SerialNumber) != 0 {
			continue
		}
		expected, err := NewCertID(subject, issuer, id.HashAlgorithmOID)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(id.IssuerNameHash, expected.IssuerNameHash) || !bytes.Equal(id.IssuerKeyHash, expected.IssuerKeyHash) {
			continue
		}
		if found != nil {
			return nil, errors.New("ocsp: duplicate matching certificate statuses")
		}
		found = single
	}
	if found == nil {
		return nil, ErrNoStatus
	}
	return found, nil
}

// Matches reports whether the complete CertID matches, without trusting status.
func (r *Response) Matches(subject, issuer *cert.Certificate) (bool, error) {
	if r == nil {
		return false, ErrNoStatus
	}
	original, err := ParseResponse(r.rawDER)
	if err != nil {
		return false, err
	}
	_, err = original.find(subject, issuer)
	if errors.Is(err, ErrNoStatus) {
		return false, nil
	}
	return err == nil, err
}

// Check authenticates a current OCSP status. maxAge bounds cached evidence even
// when NextUpdate is absent. Delegated responders must carry OCSP signing EKU
// and a valid, noncritical OCSP nocheck extension. Use CheckWithPolicy to supply
// full CRLs for responders without that exemption.
func (r *Response) Check(subject, issuer *cert.Certificate, now time.Time, maxAge, skew time.Duration) (CertStatus, error) {
	return r.CheckWithPolicy(subject, issuer, ValidationPolicy{Time: now, MaxAge: maxAge, ClockSkew: skew})
}

// ValidationPolicy supplies freshness limits and optional full CRLs for delegated responders.
type ValidationPolicy struct {
	Time               time.Time
	MaxAge, ClockSkew  time.Duration
	ResponderCRLs      [][]byte
	MaxResponderCRLAge time.Duration // zero selects seven days
}

// CheckWithPolicy authenticates status and the delegated responder revocation evidence.
func (r *Response) CheckWithPolicy(subject, issuer *cert.Certificate, policy ValidationPolicy) (CertStatus, error) {
	if r == nil {
		return Unknown, ErrNoStatus
	}
	if policy.MaxResponderCRLAge < 0 {
		return Unknown, errors.New("ocsp: invalid CRL freshness policy")
	}
	if policy.MaxResponderCRLAge == 0 {
		policy.MaxResponderCRLAge = 7 * 24 * time.Hour
	}
	// Authenticate the signed wire snapshot, never caller-modifiable display fields.
	original, err := ParseResponse(r.rawDER)
	if err != nil {
		return Unknown, err
	}
	return original.check(subject, issuer, policy)
}

func (r *Response) check(subject, issuer *cert.Certificate, policy ValidationPolicy) (CertStatus, error) {
	now, maxAge, skew := policy.Time, policy.MaxAge, policy.ClockSkew
	if maxAge <= 0 || skew < 0 {
		return Unknown, errors.New("ocsp: invalid freshness policy")
	}
	if issuer == nil || now.Before(issuer.NotBefore) || now.After(issuer.NotAfter) {
		return Unknown, errors.New("ocsp: issuer is not currently valid")
	}
	single, err := r.find(subject, issuer)
	if err != nil {
		return Unknown, err
	}
	if err := cert.VerifyCertAt(subject, issuer, now); err != nil {
		return Unknown, err
	}
	if err := r.verifyAuthorized(issuer, now, policy.ResponderCRLs, policy.MaxResponderCRLAge, skew); err != nil {
		return Unknown, err
	}
	if r.ProducedAt.IsZero() || single.ThisUpdate.IsZero() || r.ProducedAt.After(now.Add(skew)) || single.ThisUpdate.After(now.Add(skew)) || r.ProducedAt.Before(single.ThisUpdate.Add(-skew)) || now.Sub(single.ThisUpdate) > maxAge+skew || now.Sub(r.ProducedAt) > maxAge+skew {
		return Unknown, errors.New("ocsp: stale or future status evidence")
	}
	if !single.NextUpdate.IsZero() && (single.NextUpdate.Before(single.ThisUpdate) || now.After(single.NextUpdate.Add(skew))) {
		return Unknown, errors.New("ocsp: status evidence has expired")
	}
	switch single.Status {
	case Good:
		return Good, nil
	case Revoked:
		if single.RevocationTime.IsZero() || single.RevocationTime.After(single.ThisUpdate.Add(skew)) {
			return Unknown, errors.New("ocsp: invalid revocation time")
		}
		return Revoked, ErrRevoked
	default:
		return Unknown, ErrUnknown
	}
}
