package dstu4145

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"

	"github.com/stretchr/testify/require"
)

// TestSignVerifyRoundtrip tests sign+verify on all 10 DSTU curves.
func TestSignVerifyRoundtrip(t *testing.T) {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}

	for _, p := range AllParams() {
		t.Run(p.Name, func(t *testing.T) {
			priv, err := GenerateKey(p.Curve)
			require.NoError(t, err, "GenerateKey")
			pub := priv.Public()

			sig, err := Sign(rand.Reader, priv, digest)
			require.NoError(t, err, "Sign")

			require.True(t, Verify(pub, digest, sig), "Verify returned false for valid signature")
		})
	}
}

// TestInvalidSignature verifies that tampered signatures are rejected.
func TestInvalidSignature(t *testing.T) {
	curve := ec.DSTU_PB_257()
	digest := []byte("test hash value padded to 32byte")

	priv, err := GenerateKey(curve)
	require.NoError(t, err)
	pub := priv.Public()

	sig, err := Sign(rand.Reader, priv, digest)
	require.NoError(t, err)

	// Tamper with S
	badSig := &Signature{R: sig.R.Clone(), S: new(big.Int).Add(sig.S, big.NewInt(1))}
	require.False(t, Verify(pub, digest, badSig), "Verify accepted tampered S")

	// Tamper with R (use an obviously different element — all low bits set)
	badR := sig.R.Clone()
	for i := range curve.Words * 32 {
		badR.SetBit(i)
	}
	// badR is now all-ones (max field element); extremely unlikely to equal r'
	require.False(t, Verify(pub, digest, &Signature{R: badR, S: sig.S}), "Verify accepted tampered R (all-ones)")
}

// TestWrongKey verifies that a signature from one key is rejected by another.
func TestWrongKey(t *testing.T) {
	curve := ec.DSTU_PB_257()
	digest := make([]byte, 32)

	priv1, _ := GenerateKey(curve)
	priv2, _ := GenerateKey(curve)

	sig, err := Sign(rand.Reader, priv1, digest)
	require.NoError(t, err)

	pub2 := priv2.Public()
	require.False(t, Verify(pub2, digest, sig), "Verify accepted signature from wrong key")
}

// TestMarshalRoundtrip tests ASN.1 marshal/unmarshal of a signature.
func TestMarshalRoundtrip(t *testing.T) {
	curve := ec.DSTU_PB_257()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	priv, _ := GenerateKey(curve)
	pub := priv.Public()

	sig, err := Sign(rand.Reader, priv, digest)
	require.NoError(t, err)

	der, err := MarshalSignature(sig)
	require.NoError(t, err, "MarshalSignature")

	sig2, err := UnmarshalSignature(der, curve.Words)
	require.NoError(t, err, "UnmarshalSignature")

	require.True(t, sig.R.Equal(sig2.R), "R mismatch after marshal/unmarshal")
	require.Equal(t, 0, sig.S.Cmp(sig2.S), "S mismatch after marshal/unmarshal")

	require.True(t, Verify(pub, digest, sig2), "Verify failed on unmarshaled signature")
}

// TestCryptoSignerInterface verifies that PrivateKey implements [crypto.Signer].
func TestCryptoSignerInterface(t *testing.T) {
	curve := ec.DSTU_PB_257()
	digest := make([]byte, 32)

	priv, _ := GenerateKey(curve)
	pub := priv.Public()

	// Sign via the crypto.Signer interface
	der, err := priv.Sign(rand.Reader, digest, nil)
	require.NoError(t, err, "Sign (crypto.Signer)")

	sig, err := UnmarshalSignature(der, curve.Words)
	require.NoError(t, err, "UnmarshalSignature")

	require.True(t, Verify(pub, digest, sig), "Verify failed on crypto.Signer output")
}

// TestTruncate verifies that the truncate function clips hash bits correctly.
func TestTruncate(t *testing.T) {
	curve := ec.DSTU_PB_163()
	n := new(big.Int).SetBytes(curve.N)
	nBits := n.BitLen() // ~162 bits for PB_163

	// 32-byte (256-bit) hash truncated to nBits should have zero bits above nBits
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = 0xff
	}

	h := truncate(hash, nBits, curve.Words)
	words := h.Words()
	// All bits from nBits upward should be zero
	for bit := nBits; bit < curve.Words*32; bit++ {
		require.False(t, h.TestBit(bit), "truncate: bit %d should be zero (nBits=%d)", bit, nBits)
	}
	_ = words
}

// TestFieldElemToInt checks the round-trip of fieldElemToInt.
func TestFieldElemToInt(t *testing.T) {
	words := 9 // PB_257
	e, err := gf2m.FromHex("deadbeef01234567", words)
	if err != nil {
		t.Fatal(err)
	}

	i := fieldElemToInt(e)
	require.NotEqual(t, 0, i.Sign(), "fieldElemToInt returned 0 for nonzero element")
	// Convert back via big.Int bytes → big-endian → FromBytes
	b := i.Bytes()
	e2 := gf2m.FromBytes(b, words)
	require.True(t, e.Equal(e2), "round-trip failed: got %s, want %s", e2, e)
}

// TestParamsByName verifies OID/name lookup.
func TestParamsByName(t *testing.T) {
	p := ParamsByName("DSTU_PB_257")
	require.NotNil(t, p, "ParamsByName(DSTU_PB_257)")
	require.Equal(t, 257, p.Curve.M, "wrong curve M")

	p2 := ParamsByOID(OIDCurvePB257)
	require.NotNil(t, p2, "ParamsByOID")
	require.Equal(t, "DSTU_PB_257", p2.Name, "wrong name from OID")
}

func TestRandomScalarUsesDSTUBitLength(t *testing.T) {
	for _, parameters := range AllParams() {
		t.Run(parameters.Name, func(t *testing.T) {
			order := new(big.Int).SetBytes(parameters.Curve.N)
			size := (order.BitLen() + 7) / 8
			// All-one entropy must produce the largest permitted scalar, even
			// when n itself would allow additional values with L(k) = L(n).
			scalar, err := randFieldElement(bytes.NewReader(bytes.Repeat([]byte{0xff}, size)), order)
			require.NoError(t, err)
			maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(order.BitLen()-1)), big.NewInt(1))
			require.Zero(t, scalar.Cmp(maximum))
			require.Less(t, scalar.BitLen(), order.BitLen())
			// A zero draw is retried; the next draw can select the minimum.
			entropy := make([]byte, 2*size)
			entropy[len(entropy)-1] = 1
			scalar, err = randFieldElement(bytes.NewReader(entropy), order)
			require.NoError(t, err)
			require.Equal(t, int64(1), scalar.Int64())
			_, err = randFieldElement(bytes.NewReader(nil), order)
			require.Error(t, err)
		})
	}
}

func TestSignatureNonceUsesDSTUBitLength(t *testing.T) {
	for _, parameters := range AllParams() {
		t.Run(parameters.Name, func(t *testing.T) {
			order := new(big.Int).SetBytes(parameters.Curve.N)
			maximum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(order.BitLen()-1)), big.NewInt(1))
			key := &PrivateKey{D: big.NewInt(1), Curve: parameters.Curve}
			digest := []byte{1}
			signature, err := Sign(bytes.NewReader(bytes.Repeat([]byte{0xff}, (order.BitLen()+7)/8)), key, digest)
			require.NoError(t, err)
			// s = e + d*r (mod n); recover e independently from the returned signature.
			nonce := new(big.Int).Sub(signature.S, new(big.Int).SetBytes(signature.R.Bytes()))
			nonce.Mod(nonce, order)
			require.Zero(t, nonce.Cmp(maximum))
			require.True(t, Verify(key.Public(), digest, signature))
		})
	}
}
