package dstu15946

import (
	"crypto/rand"
	"testing"

	"crypto-dstu/dstu4145"
	"crypto-dstu/ec"
	"crypto-dstu/gost28147"
	"crypto-dstu/gost34311"
	"crypto-dstu/kupyna"

	"github.com/stretchr/testify/require"
)

// TestSharedSecretSymmetry verifies Alice and Bob derive the same ZZ.
// Matches cryptonite dstu4145_dh with_cofactor=true.
func TestSharedSecretSymmetry(t *testing.T) {
	curves := []*ec.Curve{
		ec.DSTU_PB_257(),
		ec.DSTU_PB_431(),
		ec.DSTU_PB_163(),
	}

	for _, curve := range curves {
		t.Run(curve.String(), func(t *testing.T) {
			alice, err := dstu4145.GenerateKey(curve)
			require.NoError(t, err)
			bob, err := dstu4145.GenerateKey(curve)
			require.NoError(t, err)

			zzA, err := SharedSecret(alice, bob.Public())
			require.NoError(t, err, "Alice SharedSecret")
			zzB, err := SharedSecret(bob, alice.Public())
			require.NoError(t, err, "Bob SharedSecret")

			require.Equal(t, zzA, zzB, "shared secrets differ")

			// ZZ must be exactly ceil(m/8) bytes
			require.Len(t, zzA, (curve.M+7)/8, "ZZ length")
		})
	}
}

// TestDifferentKeysGiveDifferentSecrets verifies two unrelated key pairs produce different ZZ.
func TestDifferentKeysGiveDifferentSecrets(t *testing.T) {
	curve := ec.DSTU_PB_257()

	alice, _ := dstu4145.GenerateKey(curve)
	bob, _ := dstu4145.GenerateKey(curve)
	carol, _ := dstu4145.GenerateKey(curve)

	zzAB, err := SharedSecret(alice, bob.Public())
	require.NoError(t, err)
	zzAC, err := SharedSecret(alice, carol.Public())
	require.NoError(t, err)

	require.NotEqual(t, zzAB, zzAC, "different peer keys produced the same shared secret")
}

// TestDeriveKeyDeterminism verifies DeriveKey is deterministic.
func TestDeriveKeyDeterminism(t *testing.T) {
	zz := make([]byte, 32)
	for i := range zz {
		zz[i] = byte(i + 1)
	}
	ukm := make([]byte, 8)
	for i := range ukm {
		ukm[i] = byte(i + 0x10)
	}

	k1, err := DeriveKey(zz, ukm, gost34311.New)
	require.NoError(t, err)
	k2, err := DeriveKey(zz, ukm, gost34311.New)
	require.NoError(t, err)

	require.Equal(t, k1, k2, "DeriveKey is not deterministic")
	require.Len(t, k1, 32, "KEK length")
}

// TestDeriveKeyDifferentUKM verifies different UKM produces different KEK.
func TestDeriveKeyDifferentUKM(t *testing.T) {
	zz := make([]byte, 32)
	for i := range zz {
		zz[i] = byte(i + 1)
	}

	k1, _ := DeriveKey(zz, []byte("ukm-value-one!!!"), gost34311.New)
	k2, _ := DeriveKey(zz, []byte("ukm-value-two!!!"), gost34311.New)

	require.NotEqual(t, k1, k2, "different UKMs produced the same KEK")
}

// TestDeriveKeyNilUKM verifies DeriveKey works with nil UKM.
func TestDeriveKeyNilUKM(t *testing.T) {
	zz := make([]byte, 32)
	rand.Read(zz)

	k, err := DeriveKey(zz, nil, gost34311.New)
	require.NoError(t, err, "DeriveKey(nil ukm)")
	require.Len(t, k, 32, "KEK length")
}

// TestKeyAgreementWithGost34311 verifies full KeyAgreement roundtrip with GOST 34.311 hash.
func TestKeyAgreementWithGost34311(t *testing.T) {
	curve := ec.DSTU_PB_257()
	ukm := make([]byte, 8)
	rand.Read(ukm)

	alice, _ := dstu4145.GenerateKey(curve)
	bob, _ := dstu4145.GenerateKey(curve)

	kekA, err := KeyAgreement(alice, bob.Public(), ukm, gost34311.New)
	require.NoError(t, err, "Alice KeyAgreement")
	kekB, err := KeyAgreement(bob, alice.Public(), ukm, gost34311.New)
	require.NoError(t, err, "Bob KeyAgreement")

	require.Equal(t, kekA, kekB, "KEKs differ")
}

// TestKeyAgreementWithKupyna verifies full KeyAgreement roundtrip with Kupyna-256 hash.
func TestKeyAgreementWithKupyna(t *testing.T) {
	curve := ec.DSTU_PB_257()
	ukm := []byte("test-ukm-value!!")

	alice, _ := dstu4145.GenerateKey(curve)
	bob, _ := dstu4145.GenerateKey(curve)

	kekA, err := KeyAgreement(alice, bob.Public(), ukm, kupyna.New256)
	require.NoError(t, err, "Alice KeyAgreement (Kupyna)")
	kekB, err := KeyAgreement(bob, alice.Public(), ukm, kupyna.New256)
	require.NoError(t, err, "Bob KeyAgreement (Kupyna)")

	require.Equal(t, kekA, kekB, "Kupyna KEKs differ")
}

// TestSharedInfoDER verifies the DER-encoded SharedInfo has expected structure.
func TestSharedInfoDER(t *testing.T) {
	ukm := []byte{0x01, 0x02, 0x03, 0x04}
	der, err := sharedInfoDER(ukm)
	require.NoError(t, err, "sharedInfoDER")
	require.NotEmpty(t, der, "sharedInfoDER returned empty bytes")

	// No-UKM variant must differ
	derNoUKM, _ := sharedInfoDER(nil)
	require.NotEqual(t, der, derNoUKM, "SharedInfo with and without UKM should differ")
}

// TestSboxDSTUImport just ensures the gost28147 import compiles
// (the sbox is used in GOST 34.311 hash which is used in key derivation).
func TestSboxDSTUImport(_ *testing.T) {
	_ = gost28147.SboxDSTU
}
