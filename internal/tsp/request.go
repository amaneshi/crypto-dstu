package tsp

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
)

// MessageImprint holds the hash algorithm OID and the hashed message bytes.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// Request is an RFC 3161 TimeStampReq.
type Request struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     asn1.RawValue         `asn1:"optional,implicit,tag:0"`
}

// NewRequest builds a TSP request for the given pre-computed hash and algorithm OID.
// A random 128-bit nonce is generated automatically; CertReq is set to true.
func NewRequest(hash []byte, hashAlgOID asn1.ObjectIdentifier) (*Request, error) {
	if len(hash) == 0 {
		return nil, errors.New("tsp: hash must not be empty")
	}
	if len(hashAlgOID) == 0 {
		return nil, errors.New("tsp: hashAlgOID must not be empty")
	}

	if err := validImprint(MessageImprint{HashAlgorithm: AlgorithmIdentifier{Algorithm: hashAlgOID}, HashedMessage: hash}); err != nil {
		return nil, err
	}
	nonceBuf := make([]byte, 16)
	if _, err := rand.Read(nonceBuf); err != nil {
		return nil, errors.New("tsp: generate nonce: " + err.Error())
	}
	nonce := new(big.Int).SetBytes(nonceBuf)

	return &Request{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: hashAlgOID},
			HashedMessage: bytes.Clone(hash),
		},
		Nonce:   nonce,
		CertReq: true,
	}, nil
}

// Marshal encodes the request to DER.
func (r *Request) Marshal() ([]byte, error) {
	return asn1.Marshal(*r)
}
