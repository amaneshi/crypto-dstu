package ocsp

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/pkg/dstu4145"
	"crypto-dstu/pkg/gost34311"
	"crypto-dstu/pkg/kupyna"
)

// CertStatus represents the revocation status of a certificate.
type CertStatus int

const (
	// Good means the certificate is not revoked.
	Good CertStatus = 0
	// Revoked means the certificate has been revoked.
	Revoked CertStatus = 1
	// Unknown means the responder does not know about the certificate.
	Unknown CertStatus = 2
)

// SingleResponse holds the status of one certificate in an OCSP response.
type SingleResponse struct {
	CertID         CertID
	Status         CertStatus
	RevocationTime time.Time // zero if Status != Revoked
	ThisUpdate     time.Time
	NextUpdate     time.Time
}

// Response holds a parsed OCSP response.
type Response struct {
	Status       int // 0 = successful
	ProducedAt   time.Time
	Responses    []SingleResponse
	Certificates []*cert.Certificate

	// tbsResponseDataRaw holds the signed portion for Verify.
	tbsResponseDataRaw []byte
	// sigAlgOID is the signature algorithm.
	sigAlgOID asn1.ObjectIdentifier
	// signature bytes.
	sigBytes []byte
}

// --- internal ASN.1 structures for OCSPResponse ---

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type ocspResponseASN1 struct {
	ResponseStatus int
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
	Version            int           `asn1:"explicit,tag:0,optional"`
	ResponderID        asn1.RawValue `asn1:"choice"`
	ProducedAt         time.Time
	Responses          []singleResponseASN1
	ResponseExtensions asn1.RawValue `asn1:"explicit,tag:1,optional"`
}

type singleResponseASN1 struct {
	CertID           certID
	CertStatus       asn1.RawValue
	ThisUpdate       time.Time
	NextUpdate       time.Time     `asn1:"explicit,tag:0,optional"`
	SingleExtensions asn1.RawValue `asn1:"explicit,tag:1,optional"`
}

type revokedInfo struct {
	RevocationTime   time.Time
	RevocationReason asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// OID for BasicOCSPResponse (RFC 6960).
var oidBasicOCSPResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// ParseResponse parses a DER-encoded OCSPResponse.
func ParseResponse(der []byte) (*Response, error) {
	var outer ocspResponseASN1
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, errors.New("ocsp: parse response: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("ocsp: parse response: trailing data")
	}

	resp := &Response{Status: outer.ResponseStatus}
	if outer.ResponseStatus != 0 {
		// Non-successful (e.g. malformedRequest=1, internalError=2, etc.)
		return resp, nil
	}

	if !outer.ResponseBytes.ResponseType.Equal(oidBasicOCSPResponse) {
		return nil, errors.New("ocsp: unsupported response type: " + outer.ResponseBytes.ResponseType.String())
	}

	var basic basicOCSPResponse
	if _, err = asn1.Unmarshal(outer.ResponseBytes.Response, &basic); err != nil {
		return nil, errors.New("ocsp: parse BasicOCSPResponse: " + err.Error())
	}

	resp.tbsResponseDataRaw = basic.TBSResponseData.FullBytes
	resp.sigAlgOID = basic.SignatureAlgorithm.Algorithm
	resp.sigBytes = basic.Signature.Bytes

	var tbs responseData
	if _, err = asn1.Unmarshal(basic.TBSResponseData.FullBytes, &tbs); err != nil {
		return nil, errors.New("ocsp: parse ResponseData: " + err.Error())
	}

	resp.ProducedAt = tbs.ProducedAt

	for _, sr := range tbs.Responses {
		single := parseSingleResponse(sr)
		resp.Responses = append(resp.Responses, single)
	}

	// Parse embedded certificates if present.
	if len(basic.Certs.Bytes) > 0 {
		if certs, certsErr := cert.ParseCertificates(basic.Certs.Bytes); certsErr == nil {
			resp.Certificates = certs
		}
	}

	return resp, nil
}

// Verify checks the OCSP response signature against the issuer's public key.
func (r *Response) Verify(issuer *cert.Certificate) error {
	if issuer == nil {
		return errors.New("ocsp: verify: nil issuer")
	}
	if issuer.PublicKey == nil {
		return errors.New("ocsp: verify: issuer has no DSTU public key")
	}
	if len(r.tbsResponseDataRaw) == 0 {
		return errors.New("ocsp: verify: no TBSResponseData to verify")
	}

	digest, err := hashResponseData(r.tbsResponseDataRaw, r.sigAlgOID)
	if err != nil {
		return errors.New("ocsp: verify: hash: " + err.Error())
	}

	sig, err := dstu4145.UnmarshalSignature(r.sigBytes, issuer.PublicKey.Curve.Words)
	if err != nil {
		return errors.New("ocsp: verify: unmarshal signature: " + err.Error())
	}

	if !dstu4145.Verify(issuer.PublicKey, digest, sig) {
		return errors.New("ocsp: verify: signature verification failed")
	}
	return nil
}

// parseSingleResponse decodes one SingleResponse entry.
func parseSingleResponse(sr singleResponseASN1) SingleResponse {
	id := CertID{
		HashAlgorithmOID: sr.CertID.HashAlgorithm.Algorithm,
		IssuerNameHash:   sr.CertID.IssuerNameHash,
		IssuerKeyHash:    sr.CertID.IssuerKeyHash,
		SerialNumber:     sr.CertID.SerialNumber,
	}
	if id.SerialNumber == nil {
		id.SerialNumber = new(big.Int)
	}

	s := SingleResponse{
		CertID:     id,
		ThisUpdate: sr.ThisUpdate,
		NextUpdate: sr.NextUpdate,
	}

	// CertStatus is CHOICE: [0] good (NULL), [1] revoked (RevokedInfo), [2] unknown (NULL)
	switch sr.CertStatus.Tag {
	case 0:
		s.Status = Good
	case 1:
		s.Status = Revoked
		var ri revokedInfo
		if _, err := asn1.UnmarshalWithParams(sr.CertStatus.FullBytes, &ri, "explicit,tag:1"); err == nil {
			s.RevocationTime = ri.RevocationTime
		}
	default:
		s.Status = Unknown
	}

	return s
}

// hashResponseData hashes tbsData using the algorithm indicated by sigAlgOID.
func hashResponseData(data []byte, sigAlgOID asn1.ObjectIdentifier) ([]byte, error) {
	var h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}

	switch {
	case sigAlgOID.Equal(oidDSTU4145WithGOST34311):
		h = gost34311.New()
	case sigAlgOID.Equal(oidDSTU4145WithKupyna256):
		h = kupyna.New256()
	case sigAlgOID.Equal(oidDSTU4145WithKupyna512):
		h = kupyna.New512()
	default:
		return nil, errors.New("ocsp: unsupported signature algorithm: " + sigAlgOID.String())
	}

	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

// Signature algorithm OIDs used in OCSP responses (same as cert OIDs).
var (
	oidDSTU4145WithGOST34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	oidDSTU4145WithKupyna256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2}
	oidDSTU4145WithKupyna512 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 3}
)
