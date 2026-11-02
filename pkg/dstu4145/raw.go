package dstu4145

import (
	"errors"
	"math/big"

	"crypto-dstu/pkg/ec"
	"crypto-dstu/pkg/gf2m"
)

// MarshalSignatureRaw encodes r LE || s LE with each component sized to the
// curve order, as required by the Ukrainian CMS profile.
func MarshalSignatureRaw(sig *Signature, curve *ec.Curve) ([]byte, error) {
	if curve == nil || sig == nil || sig.S == nil {
		return nil, errors.New("dstu4145: missing signature or curve")
	}
	n := new(big.Int).SetBytes(curve.N)
	r := new(big.Int).SetBytes(sig.R.Bytes())
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
		return nil, errors.New("dstu4145: signature component out of range")
	}
	size := (n.BitLen() + 7) / 8
	out := make([]byte, 2*size)
	for i, b := range reverseRaw(r.Bytes()) {
		out[i] = b
	}
	for i, b := range reverseRaw(sig.S.Bytes()) {
		out[size+i] = b
	}
	return out, nil
}

// UnmarshalSignatureRaw decodes the fixed-width Ukrainian CMS representation.
func UnmarshalSignatureRaw(raw []byte, curve *ec.Curve) (*Signature, error) {
	if curve == nil {
		return nil, errors.New("dstu4145: missing curve")
	}
	n := new(big.Int).SetBytes(curve.N)
	size := (n.BitLen() + 7) / 8
	if len(raw) != 2*size {
		return nil, errors.New("dstu4145: invalid raw signature length")
	}
	r := new(big.Int).SetBytes(reverseRaw(raw[:size]))
	s := new(big.Int).SetBytes(reverseRaw(raw[size:]))
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return nil, errors.New("dstu4145: signature component out of range")
	}
	return &Signature{R: gf2m.FromBytes(r.Bytes(), curve.Words), S: s}, nil
}

func reverseRaw(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[len(b)-1-i] = v
	}
	return r
}
