// Package dstu4145 implements the DSTU 4145-2002 elliptic curve digital signature algorithm.
// Reference: jkurwa lib/models/Priv.js, Pub.js, lib/curve.js
package dstu4145

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"crypto-dstu/ec"
	"crypto-dstu/gf2m"
)

// PrivateKey holds a DSTU 4145 private key.
type PrivateKey struct {
	D     *big.Int  // private scalar d ∈ [1, n-1]
	Curve *ec.Curve // domain parameters
}

// PublicKey holds a DSTU 4145 public key.
type PublicKey struct {
	Q     *ec.Point // public point Q = d·G
	Curve *ec.Curve
}

// Signature holds a DSTU 4145 signature.
type Signature struct {
	R gf2m.Element // r value — field element (NOT just an integer)
	S *big.Int     // s value — integer mod n
}

// Public derives the public key from the private key.
func (priv *PrivateKey) Public() *PublicKey {
	q := priv.Curve.ScalarBaseMul(priv.D)
	return &PublicKey{Q: q, Curve: priv.Curve}
}

// Public implements crypto.Signer.
func (priv *PrivateKey) PublicKey() crypto.PublicKey {
	return priv.Public()
}

// GenerateKey generates a random DSTU 4145 private key for the given curve.
func GenerateKey(curve *ec.Curve) (*PrivateKey, error) {
	n := new(big.Int).SetBytes(curve.N)
	for {
		d, err := randFieldElement(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		priv := &PrivateKey{D: d, Curve: curve}
		q := priv.Public().Q
		if !q.IsInfinity() && curve.Contains(q) {
			return priv, nil
		}
	}
}

// Sign signs the pre-hashed digest using the private key.
// Implements crypto.Signer.
func (priv *PrivateKey) Sign(rng io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig, err := Sign(rng, priv, digest)
	if err != nil {
		return nil, err
	}
	return MarshalSignature(sig)
}

// Sign produces a DSTU 4145 signature over a pre-hashed message digest.
// digest should already be the output of a hash function (e.g. GOST 34.311 or Kupyna-256).
func Sign(rng io.Reader, priv *PrivateKey, digest []byte) (*Signature, error) {
	if rng == nil {
		rng = rand.Reader
	}
	curve := priv.Curve
	n := new(big.Int).SetBytes(curve.N)

	// Truncate hash to curve order bit length
	h := truncate(digest, n.BitLen(), curve.Words)
	if h.IsZero() {
		// h = 1 per jkurwa spec
		one, _ := gf2m.FromHex("1", curve.Words)
		h = one
	}

	for {
		// Random ephemeral scalar e ∈ [1, n-1]
		e, err := randFieldElement(rng, n)
		if err != nil {
			return nil, err
		}

		// R = e·G
		R := curve.ScalarBaseMul(e)
		if R.IsInfinity() {
			continue
		}

		// r = (xR * h) mod f(x)  — field multiplication
		r := gf2m.ModMul(R.X, h, curve.ModBits)
		if r.IsZero() {
			continue
		}

		// r_int = fieldElement → integer, then mod n
		rInt := fieldElemToInt(r)
		rInt.Mod(rInt, n)
		if rInt.Sign() == 0 {
			continue
		}

		// s = (e + d * r_int) mod n
		s := new(big.Int).Mul(priv.D, rInt)
		s.Add(s, e)
		s.Mod(s, n)
		if s.Sign() == 0 {
			continue
		}

		return &Signature{R: r, S: s}, nil
	}
}

// Verify verifies a DSTU 4145 signature against the public key and digest.
func Verify(pub *PublicKey, digest []byte, sig *Signature) bool {
	if sig == nil || sig.S == nil {
		return false
	}
	curve := pub.Curve
	n := new(big.Int).SetBytes(curve.N)

	// Validate s ∈ [1, n-1]
	if sig.S.Sign() <= 0 || sig.S.Cmp(n) >= 0 {
		return false
	}

	// Truncate hash
	h := truncate(digest, n.BitLen(), curve.Words)
	if h.IsZero() {
		one, _ := gf2m.FromHex("1", curve.Words)
		h = one
	}

	// r_int from signature field element
	rInt := fieldElemToInt(sig.R)
	rInt.Mod(rInt, n)
	if rInt.Sign() == 0 {
		return false
	}

	// R' = s·G + r_int·(-Q)  (equivalent to s·G - r_int·Q)
	sG := curve.ScalarBaseMul(sig.S)
	rQ := pub.Q.ScalarMul(rInt)
	Rprime := sG.Add(rQ.Neg())

	if Rprime.IsInfinity() {
		return false
	}

	// r' = (xR' * h) mod f(x)
	rprime := gf2m.ModMul(Rprime.X, h, curve.ModBits)

	return rprime.Equal(sig.R)
}

// truncate clips a hash byte slice to fit within nBits, returning a field element.
// Matches jkurwa curve.truncate(): take the low nBits of the hash interpreted as a bit string.
func truncate(hash []byte, nBits int, words int) gf2m.Element {
	// Convert hash bytes to a field element (big-endian bytes → LE words)
	elem := gf2m.FromBytes(hash, words)
	// Mask off bits above nBits
	maskBit := nBits
	totalBits := words * 32
	for i := maskBit; i < totalBits; i++ {
		elem.ClearBit(i)
	}
	return elem
}

// fieldElemToInt interprets a field element's LE words as a big integer.
// The element words are LE uint32, so word[0] is least-significant.
func fieldElemToInt(e gf2m.Element) *big.Int {
	words := e.Words()
	// Build big-endian byte slice: word[n-1]..word[0]
	b := make([]byte, len(words)*4)
	for i, w := range words {
		j := len(words) - 1 - i
		b[j*4] = byte(w >> 24)
		b[j*4+1] = byte(w >> 16)
		b[j*4+2] = byte(w >> 8)
		b[j*4+3] = byte(w)
	}
	return new(big.Int).SetBytes(b)
}

// randFieldElement returns a random integer in [1, max-1].
func randFieldElement(rng io.Reader, max *big.Int) (*big.Int, error) {
	b := make([]byte, (max.BitLen()+7)/8)
	for {
		if _, err := io.ReadFull(rng, b); err != nil {
			return nil, errors.New("dstu4145: rand read failed: " + err.Error())
		}
		// Mask top bits to avoid bias
		if excess := uint(len(b)*8) - uint(max.BitLen()); excess > 0 {
			b[0] >>= excess
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(max) < 0 {
			return k, nil
		}
	}
}
