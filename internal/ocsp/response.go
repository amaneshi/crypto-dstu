package ocsp

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
)

type CertStatus int

const (
	Good CertStatus = iota
	Revoked
	Unknown
)

type SingleResponse struct {
	CertID         CertID
	Status         CertStatus
	RevocationTime time.Time
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

// Response is parsed evidence. Parsing alone does not authenticate its status.
type Response struct {
	Status             int
	ProducedAt         time.Time
	Responses          []SingleResponse
	Certificates       []*cert.Certificate
	tbsResponseDataRaw []byte
	sigAlgOID          asn1.ObjectIdentifier
	sigBytes           []byte
	responderID        asn1.RawValue
	rawDER             []byte
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}
type ocspResponseASN1 struct {
	ResponseStatus asn1.Enumerated
	ResponseBytes  responseBytes `asn1:"explicit,tag:0,optional"`
}
type basicOCSPResponse struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm algorithmIdentifier
	Signature          asn1.BitString
	Certs              asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type responseData struct {
	Raw                asn1.RawContent
	Version            int `asn1:"explicit,tag:0,optional,default:0"`
	ResponderID        asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []singleResponseASN1
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type singleResponseASN1 struct {
	CertID           certID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"explicit,tag:0,optional,generalized"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type revokedInfo struct {
	RevocationTime   time.Time       `asn1:"generalized"`
	RevocationReason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

var oidBasicOCSPResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// ParseResponse decodes bounded DER and rejects malformed status choices.
func ParseResponse(der []byte) (*Response, error) {
	if len(der) == 0 || len(der) > 4<<20 {
		return nil, errors.New("ocsp: response size is invalid")
	}
	der = bytes.Clone(der)
	var outer ocspResponseASN1
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 {
		return nil, errors.New("ocsp: malformed response")
	}
	r := &Response{Status: int(outer.ResponseStatus), rawDER: der}
	if r.Status != 0 {
		return r, nil
	}
	if !outer.ResponseBytes.ResponseType.Equal(oidBasicOCSPResponse) {
		return nil, errors.New("ocsp: unsupported response type")
	}
	var basic basicOCSPResponse
	if rest, err := asn1.Unmarshal(outer.ResponseBytes.Response, &basic); err != nil || len(rest) != 0 || basic.Signature.BitLength != len(basic.Signature.Bytes)*8 || len(basic.Signature.Bytes) == 0 {
		return nil, errors.New("ocsp: malformed basic response")
	}
	var tbs responseData
	rest, err := asn1.Unmarshal(basic.TBSResponseData.FullBytes, &tbs)
	if err != nil {
		return nil, fmt.Errorf("ocsp: malformed response data: %w", err)
	}
	if len(rest) != 0 || tbs.Version != 0 || len(tbs.Responses) == 0 || len(tbs.Responses) > 256 {
		return nil, errors.New("ocsp: malformed response data")
	}
	if err := checkExtensions(tbs.ResponseExtensions); err != nil {
		return nil, err
	}
	r.tbsResponseDataRaw = basic.TBSResponseData.FullBytes
	r.sigAlgOID, r.sigBytes, r.responderID = basic.SignatureAlgorithm.Algorithm, basic.Signature.Bytes, tbs.ResponderID
	r.ProducedAt = tbs.ProducedAt
	for _, encoded := range tbs.Responses {
		if err := checkExtensions(encoded.SingleExtensions); err != nil {
			return nil, err
		}
		single, err := parseSingleResponse(encoded)
		if err != nil {
			return nil, err
		}
		r.Responses = append(r.Responses, single)
	}
	if len(basic.Certs.Bytes) != 0 {
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(basic.Certs.Bytes, &sequence); err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence || sequence.Class != 0 {
			return nil, errors.New("ocsp: malformed responder certificates")
		}
		var err error
		r.Certificates, err = cert.ParseCertificates(sequence.Bytes)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func checkExtensions(extensions []pkix.Extension) error {
	seen := map[string]bool{}
	for _, ext := range extensions {
		if ext.Critical || seen[ext.Id.String()] {
			return errors.New("ocsp: critical or duplicate response extension")
		}
		seen[ext.Id.String()] = true
	}
	return nil
}

func parseSingleResponse(sr singleResponseASN1) (SingleResponse, error) {
	id := CertID{HashAlgorithmOID: sr.CertID.HashAlgorithm.Algorithm, IssuerNameHash: sr.CertID.IssuerNameHash, IssuerKeyHash: sr.CertID.IssuerKeyHash, SerialNumber: sr.CertID.SerialNumber}
	if id.SerialNumber == nil || id.SerialNumber.Sign() <= 0 {
		return SingleResponse{}, errors.New("ocsp: invalid certificate serial")
	}
	s := SingleResponse{CertID: id, ThisUpdate: sr.ThisUpdate, NextUpdate: sr.NextUpdate}
	status := sr.CertStatus
	if status.Class != 2 {
		return s, errors.New("ocsp: invalid status class")
	}
	switch status.Tag {
	case 0, 2:
		if status.IsCompound || len(status.Bytes) != 0 {
			return s, errors.New("ocsp: malformed good/unknown status")
		}
		if status.Tag == 2 {
			s.Status = Unknown
		}
	case 1:
		if !status.IsCompound {
			return s, errors.New("ocsp: malformed revoked status")
		}
		wrapped, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: status.Bytes})
		if err != nil {
			return s, err
		}
		var revoked revokedInfo
		if rest, err := asn1.Unmarshal(wrapped, &revoked); err != nil || len(rest) != 0 || revoked.RevocationTime.IsZero() {
			return s, errors.New("ocsp: malformed revocation information")
		}
		s.Status, s.RevocationTime = Revoked, revoked.RevocationTime
	default:
		return s, errors.New("ocsp: unsupported status choice")
	}
	return s, nil
}

// Verify checks an issuer-signed response's identity and signature only.
// Use Check to validate certificate binding, responder delegation and freshness.
func (r *Response) Verify(issuer *cert.Certificate) error {
	if r == nil || r.Status != 0 || issuer == nil || !r.responderMatches(issuer) {
		return errors.New("ocsp: response does not identify the issuer")
	}
	return cert.VerifyDataSignature(r.tbsResponseDataRaw, r.sigBytes, r.sigAlgOID, issuer.PublicKey)
}
