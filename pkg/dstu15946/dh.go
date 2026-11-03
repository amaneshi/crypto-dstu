// Package dstu15946 implements EC Diffie-Hellman key agreement as specified in
// DSTU ISO/IEC 15946-3:2006.
// Reference: cryptonite dstu4145.c — dstu4145_dh()
package dstu15946

import (
	"errors"
	"math/big"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
)

// SharedSecret computes the ECDH shared secret, matching cryptonite dstu4145_dh
// with with_cofactor=true:
//
//  1. Validate cofactor·peer.Q ≠ O  (peer key is in the correct subgroup)
//  2. S  = priv.D · peer.Q
//  3. S  = S · cofactor              (two separate scalar multiplications)
//
// Returns the x-coordinate of S as exactly ceil(m/8) big-endian bytes.
func SharedSecret(priv *dstu4145.PrivateKey, peer *dstu4145.PublicKey) ([]byte, error) {
	return sharedSecret(priv, peer, true)
}

// SharedSecretStandard computes ECDH without cofactor multiplication. It requires
// the peer to be a nonzero point in the prime-order subgroup (n*Q = O).
// Use this only with an explicitly identified non-cofactor agreement protocol.
func SharedSecretStandard(priv *dstu4145.PrivateKey, peer *dstu4145.PublicKey) ([]byte, error) {
	return sharedSecret(priv, peer, false)
}

func sharedSecret(priv *dstu4145.PrivateKey, peer *dstu4145.PublicKey, withCofactor bool) ([]byte, error) {
	if priv == nil || priv.Curve == nil || priv.D == nil || peer == nil || peer.Curve == nil || peer.Q == nil {
		return nil, errors.New("dstu15946: missing key")
	}
	a, b := priv.Curve, peer.Curve
	if !a.EqualDomain(b) {
		return nil, errors.New("dstu15946: keys are on different curves")
	}
	curve := priv.Curve
	if peer.Q.Curve == nil || !curve.EqualDomain(peer.Q.Curve) {
		return nil, errors.New("dstu15946: point and key are on different curves")
	}
	if peer.Q.X.BitLen() > curve.M || peer.Q.Y.BitLen() > curve.M {
		return nil, errors.New("dstu15946: peer coordinates are outside the field")
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(new(big.Int).SetBytes(curve.N)) >= 0 {
		return nil, errors.New("dstu15946: private scalar out of range")
	}
	if !curve.Contains(peer.Q) {
		return nil, errors.New("dstu15946: peer public key is not on the curve")
	}
	if peer.Q.IsInfinity() {
		return nil, errors.New("dstu15946: peer public key is infinity")
	}
	if !withCofactor && !peer.Q.ScalarMul(new(big.Int).SetBytes(curve.N)).IsInfinity() {
		return nil, errors.New("dstu15946: peer public key is not in the prime-order subgroup")
	}

	cofactor := big.NewInt(int64(curve.Cofactor))

	// Step 1: validate cofactor·Q ≠ O (matches cryptonite subgroup check)
	cofQ := peer.Q.ScalarMul(cofactor)
	if cofQ.IsInfinity() {
		return nil, errors.New("dstu15946: peer public key is not in the correct subgroup")
	}

	// Step 2: S = d · Q
	S := peer.Q.ScalarMul(priv.D) //nolint:gocritic // S is standard DSTU 4145 spec notation
	if S.IsInfinity() {
		return nil, errors.New("dstu15946: shared point is point at infinity")
	}

	// Step 3: S = S · cofactor  (matches cryptonite with_cofactor branch)
	if withCofactor {
		S = S.ScalarMul(cofactor)
	}
	if S.IsInfinity() {
		return nil, errors.New("dstu15946: shared point after cofactor mul is infinity")
	}

	// Return x-coordinate as fixed-length big-endian bytes: ceil(m/8) bytes
	byteLen := (curve.M + 7) / 8
	x, err := curve.EncodeField(S.X)
	if err != nil {
		return nil, err
	}
	return fieldElemToFixedBytes(x, byteLen), nil
}

// fieldElemToFixedBytes converts a field element to a fixed-length big-endian
// byte slice, zero-padded on the left if necessary.
func fieldElemToFixedBytes(e gf2m.Element, byteLen int) []byte {
	words := e.Words()
	// words are LE uint32; build big-endian byte slice
	raw := make([]byte, len(words)*4)
	for i, w := range words {
		j := len(words) - 1 - i
		raw[j*4] = byte(w >> 24)
		raw[j*4+1] = byte(w >> 16)
		raw[j*4+2] = byte(w >> 8)
		raw[j*4+3] = byte(w)
	}
	// Trim leading bytes to byteLen (raw may be longer due to word padding)
	if len(raw) > byteLen {
		raw = raw[len(raw)-byteLen:]
	}
	// Zero-pad on the left if shorter
	if len(raw) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(raw):], raw)
		return padded
	}
	return raw
}
