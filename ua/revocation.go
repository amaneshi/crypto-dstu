package ua

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/ocsp"
)

// RevocationPolicy selects offline verification or required authenticated OCSP.
type RevocationPolicy int

const (
	// RevocationDisabled preserves offline chain/signature verification.
	RevocationDisabled RevocationPolicy = iota
	// RevocationRequireOCSP requires fresh authenticated evidence for every
	// certificate on the validated path except its explicit trust anchor.
	RevocationRequireOCSP
)

// RevocationStatus records what revocation verification actually established.
type RevocationStatus string

const (
	RevocationNotChecked    RevocationStatus = "not-checked"
	RevocationGood          RevocationStatus = "good"
	RevocationRevoked       RevocationStatus = "revoked"
	RevocationUnknown       RevocationStatus = "unknown"
	RevocationUnavailable   RevocationStatus = "unavailable"
	RevocationNotApplicable RevocationStatus = "trust-anchor"
)

// OCSPRequest contains request bytes and untrusted certificate-advertised URLs.
// A fetch callback owns endpoint selection, network access and transport policy.
type OCSPRequest struct {
	DER           []byte
	SubjectDER    []byte
	IssuerDER     []byte
	ResponderURLs []string
}

// VerificationOptions controls current-time revocation verification. It does
// not turn discovery certificates into trust anchors or validate historical time.
type VerificationOptions struct {
	TimestampPolicy    TimestampPolicy
	TSARoots           [][]byte      // explicitly trusted TSA certificates or CA anchors (DER)
	ResponderCRLs      [][]byte      // full issuer-signed CRLs for delegated OCSP responders
	MaxResponderCRLAge time.Duration // zero selects seven days
	Revocation         RevocationPolicy
	OCSPResponses      [][]byte
	FetchOCSP          func(context.Context, OCSPRequest) ([]byte, error)
	MaxOCSPAge         time.Duration // zero selects 24 hours
	OCSPClockSkew      time.Duration // zero selects 5 minutes
}

func (o VerificationOptions) normalized() (VerificationOptions, error) {
	if o.TimestampPolicy < TimestampIgnore || o.TimestampPolicy > TimestampRequireSignature {
		return o, errors.New("ua: unsupported timestamp policy")
	}
	if o.TimestampPolicy == TimestampIgnore && len(o.TSARoots) > 0 {
		return o, errors.New("ua: TSA roots require timestamp verification")
	}
	if o.TimestampPolicy != TimestampIgnore && len(o.TSARoots) == 0 {
		return o, errors.New("ua: explicit TSA trust roots are required")
	}
	if o.Revocation != RevocationDisabled && o.Revocation != RevocationRequireOCSP {
		return o, errors.New("ua: unsupported revocation policy")
	}
	if o.Revocation == RevocationDisabled && (len(o.OCSPResponses) > 0 || len(o.ResponderCRLs) > 0 || o.FetchOCSP != nil) {
		return o, errors.New("ua: OCSP evidence requires an explicit required-revocation policy")
	}
	if o.MaxOCSPAge < 0 || o.OCSPClockSkew < 0 || o.MaxResponderCRLAge < 0 {
		return o, errors.New("ua: negative OCSP freshness policy")
	}
	if o.MaxOCSPAge == 0 {
		o.MaxOCSPAge = 24 * time.Hour
	}
	if o.OCSPClockSkew == 0 {
		o.OCSPClockSkew = 5 * time.Minute
	}
	roots := make([][]byte, len(o.TSARoots))
	for i, der := range o.TSARoots {
		roots[i] = bytes.Clone(der)
	}
	o.TSARoots = roots
	return o, nil
}

func (b *Box) checkRevocation(ctx context.Context, leaf *cert.Certificate, intermediates []*cert.Certificate, options VerificationOptions) (RevocationStatus, error) {
	if err := ctx.Err(); err != nil {
		return RevocationUnavailable, err
	}
	if options.Revocation == RevocationDisabled {
		return RevocationNotChecked, nil
	}
	chain, err := cert.BuildCertChain(leaf, b.caCerts, intermediates)
	if err != nil {
		return RevocationUnavailable, err
	}
	return checkChainRevocation(ctx, chain, options)
}

func checkChainRevocation(ctx context.Context, chain []*cert.Certificate, options VerificationOptions) (RevocationStatus, error) {
	if options.Revocation == RevocationDisabled {
		return RevocationNotChecked, nil
	}
	if err := ctx.Err(); err != nil {
		return RevocationUnavailable, err
	}
	if len(chain) == 1 {
		return RevocationNotApplicable, nil
	}
	for i := 0; i+1 < len(chain); i++ {
		status, err := checkCertificateOCSP(ctx, chain[i], chain[i+1], options)
		if err != nil {
			return status, fmt.Errorf("ua: revocation for serial %s: %w", chain[i].SerialNumber, err)
		}
		if err := ctx.Err(); err != nil {
			return RevocationUnavailable, err
		}
	}
	return RevocationGood, nil
}

func checkCertificateOCSP(ctx context.Context, subject, issuer *cert.Certificate, options VerificationOptions) (RevocationStatus, error) {
	checked := false
	check := func(der []byte) (bool, RevocationStatus, error) {
		response, err := ocsp.ParseResponse(der)
		if err != nil {
			return false, RevocationUnavailable, err
		}
		matches, err := response.Matches(subject, issuer)
		if err != nil || !matches {
			return false, RevocationUnavailable, err
		}
		status, err := response.CheckWithPolicy(subject, issuer, ocsp.ValidationPolicy{Time: time.Now(), MaxAge: options.MaxOCSPAge, ClockSkew: options.OCSPClockSkew, ResponderCRLs: options.ResponderCRLs, MaxResponderCRLAge: options.MaxResponderCRLAge})
		if errors.Is(err, ocsp.ErrRevoked) {
			return true, RevocationRevoked, err
		}
		if errors.Is(err, ocsp.ErrUnknown) {
			return true, RevocationUnknown, err
		}
		if err != nil {
			return true, RevocationUnavailable, err
		}
		if status != ocsp.Good {
			return true, RevocationUnavailable, errors.New("ua: OCSP did not establish good status")
		}
		return true, RevocationGood, nil
	}
	for _, der := range options.OCSPResponses {
		if err := ctx.Err(); err != nil {
			return RevocationUnavailable, err
		}
		matches, status, err := check(der)
		if err != nil {
			return status, err
		}
		checked = checked || matches
	}
	if !checked && options.FetchOCSP != nil {
		if err := ctx.Err(); err != nil {
			return RevocationUnavailable, err
		}
		id, err := ocsp.NewCertID(subject, issuer, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})
		if err != nil {
			return RevocationUnavailable, err
		}
		request, err := ocsp.NewRequest([]*ocsp.CertID{id})
		if err != nil {
			return RevocationUnavailable, err
		}
		der, err := request.Marshal()
		if err != nil {
			return RevocationUnavailable, err
		}
		response, err := options.FetchOCSP(ctx, OCSPRequest{DER: der, SubjectDER: bytes.Clone(subject.Raw), IssuerDER: bytes.Clone(issuer.Raw), ResponderURLs: ocsp.AIAOCSPURLs(subject)})
		if err != nil {
			return RevocationUnavailable, err
		}
		if err := ctx.Err(); err != nil {
			return RevocationUnavailable, err
		}
		matches, status, err := check(response)
		if err != nil {
			return status, err
		}
		checked = matches
	}
	if !checked {
		return RevocationUnavailable, errors.New("ua: fresh authenticated OCSP evidence is required")
	}
	return RevocationGood, nil
}
