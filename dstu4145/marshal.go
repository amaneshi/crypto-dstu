package dstu4145

import (
	"encoding/asn1"
	"errors"
	"math/big"

	"crypto-dstu/gf2m"
)

// asn1Signature is the ASN.1 encoding of a DSTU 4145 signature.
// Per DSTU convention, r is an OCTET STRING in little-endian byte order,
// and s is an INTEGER.
type asn1Signature struct {
	R []byte
	S *big.Int
}

// MarshalSignature encodes a Signature to DER-encoded ASN.1.
// The r field element is encoded as little-endian bytes (DSTU convention).
func MarshalSignature(sig *Signature) ([]byte, error) {
	if sig == nil {
		return nil, errors.New("dstu4145: nil signature")
	}
	rLE := fieldElemToLE(sig.R)
	return asn1.Marshal(asn1Signature{R: rLE, S: sig.S})
}

// UnmarshalSignature decodes a DER-encoded ASN.1 signature.
// words must match the curve word count (ceil(m/32)).
func UnmarshalSignature(der []byte, words int) (*Signature, error) {
	var raw asn1Signature
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, errors.New("dstu4145: asn1 unmarshal: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("dstu4145: trailing bytes after signature")
	}
	if raw.S == nil || raw.S.Sign() <= 0 {
		return nil, errors.New("dstu4145: invalid s value")
	}
	r := fieldElemFromLE(raw.R, words)
	return &Signature{R: r, S: raw.S}, nil
}

// fieldElemToLE converts a field element to little-endian bytes.
// Element words are already LE uint32, so just dump bytes word[0]..word[n-1].
func fieldElemToLE(e gf2m.Element) []byte {
	words := e.Words()
	b := make([]byte, len(words)*4)
	for i, w := range words {
		b[i*4] = byte(w)
		b[i*4+1] = byte(w >> 8)
		b[i*4+2] = byte(w >> 16)
		b[i*4+3] = byte(w >> 24)
	}
	// Trim trailing zero bytes
	end := len(b)
	for end > 1 && b[end-1] == 0 {
		end--
	}
	return b[:end]
}

// fieldElemFromLE creates a field element from little-endian bytes.
func fieldElemFromLE(b []byte, words int) gf2m.Element {
	// Pad to full word-aligned length
	padded := make([]byte, words*4)
	copy(padded, b)
	ws := make([]uint32, words)
	for i := 0; i < words; i++ {
		ws[i] = uint32(padded[i*4]) |
			uint32(padded[i*4+1])<<8 |
			uint32(padded[i*4+2])<<16 |
			uint32(padded[i*4+3])<<24
	}
	return gf2m.FromWords(ws)
}
