// Package ocsp implements the Online Certificate Status Protocol (RFC 6960)
// for Ukrainian PKI certificate revocation checking.
// Reference: cryptonite src/pkix/c/engine/ocsp_request_engine.c
package ocsp

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

// --- ASN.1 structures (RFC 6960) ---

type certID struct {
	HashAlgorithm  algorithmIdentifier
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type singleRequest struct {
	CertID     certID
	Extensions asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type tbsRequest struct {
	Version           int           `asn1:"explicit,tag:0,optional"`
	RequestorName     asn1.RawValue `asn1:"explicit,tag:1,optional"`
	RequestList       []singleRequest
	RequestExtensions asn1.RawValue `asn1:"explicit,tag:2,optional"`
}

type ocspRequest struct {
	TBSRequest        tbsRequest
	OptionalSignature asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// CertID identifies a certificate in an OCSP request/response.
type CertID struct {
	HashAlgorithmOID asn1.ObjectIdentifier
	IssuerNameHash   []byte
	IssuerKeyHash    []byte
	SerialNumber     *big.Int
}

// NewCertID builds a CertID for the given subject certificate and its issuer.
// hashAlgOID selects the hash algorithm; use [oid.Kupyna256] for modern UA PKI
// or [oid.GOST34311] for legacy.
func NewCertID(subject, issuer *cert.Certificate, hashAlgOID asn1.ObjectIdentifier) (*CertID, error) {
	if subject == nil || issuer == nil {
		return nil, errors.New("ocsp: nil certificate")
	}
	if subject.SerialNumber == nil || subject.SerialNumber.Sign() <= 0 {
		return nil, errors.New("ocsp: subject has no serial number")
	}
	if len(issuer.SubjectPublicKeyBytes) == 0 || len(issuer.Subject.FullBytes) == 0 {
		return nil, errors.New("ocsp: issuer encoding is unavailable")
	}

	h, err := newHashByOID(hashAlgOID)
	if err != nil {
		return nil, err
	}

	// IssuerNameHash = Hash(issuer.Subject.FullBytes)
	h.Reset()
	_, _ = h.Write(issuer.Subject.FullBytes)
	issuerNameHash := h.Sum(nil)

	// IssuerKeyHash = Hash(issuer public key bytes)
	h.Reset()
	_, _ = h.Write(issuer.SubjectPublicKeyBytes)
	issuerKeyHash := h.Sum(nil)

	return &CertID{
		HashAlgorithmOID: hashAlgOID,
		IssuerNameHash:   issuerNameHash,
		IssuerKeyHash:    issuerKeyHash,
		SerialNumber:     new(big.Int).Set(subject.SerialNumber),
	}, nil
}

// Request is a DER-encodable OCSP request (RFC 6960 OCSPRequest).
type Request struct {
	certIDs []*CertID
}

// NewRequest creates an OCSP request for the given CertIDs.
func NewRequest(ids []*CertID) (*Request, error) {
	if len(ids) == 0 {
		return nil, errors.New("ocsp: empty cert ID list")
	}
	return &Request{certIDs: ids}, nil
}

// Marshal returns the DER encoding of the OCSPRequest.
func (r *Request) Marshal() ([]byte, error) {
	var singles []singleRequest
	for _, id := range r.certIDs {
		cid := certID{
			HashAlgorithm: algorithmIdentifier{
				Algorithm: id.HashAlgorithmOID,
			},
			IssuerNameHash: id.IssuerNameHash,
			IssuerKeyHash:  id.IssuerKeyHash,
			SerialNumber:   id.SerialNumber,
		}
		singles = append(singles, singleRequest{CertID: cid})
	}

	req := ocspRequest{
		TBSRequest: tbsRequest{
			RequestList: singles,
		},
	}
	return asn1.Marshal(req)
}

// newHashByOID returns a [hash.Hash] for the given algorithm OID.
func newHashByOID(algOID asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case algOID.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}):
		return sha1.New(), nil
	case algOID.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}):
		return sha256.New(), nil
	case algOID.Equal(oid.Kupyna256):
		return kupyna.New256(), nil
	case algOID.Equal(oid.Kupyna384):
		return kupyna.New384(), nil
	case algOID.Equal(oid.Kupyna512):
		return kupyna.New512(), nil
	case algOID.Equal(oid.GOST34311):
		return gost34311.New(), nil
	default:
		return nil, errors.New("ocsp: unsupported hash algorithm: " + algOID.String())
	}
}
