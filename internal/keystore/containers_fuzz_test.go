package keystore

import (
	"bytes"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

const fuzzPassword = "public-fuzz-password"

func fuzzRawKey(t testing.TB, name string) []byte {
	t.Helper()
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName(name).Curve, D: big.NewInt(2)}
	raw, err := MarshalRawKey(key)
	require.NoError(t, err)
	return raw
}

// Bound valid KDF work in the harness, while still passing malformed/out-of-
// policy parameters to the production validator. This changes no runtime limit.
func fuzzPBES2Budget(algorithm algorithmIdentifier) bool {
	_, kdf, err := parsePBES2Parameters(algorithm)
	return err != nil || kdf.Iterations <= 256
}

func fuzzKey6Budget(data []byte) bool {
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(MaybeBase64(MaybePEM(data)), &info); err != nil {
		return true
	}
	return fuzzPBES2Budget(info.Algorithm)
}

func FuzzParseRawKey(f *testing.F) {
	for _, params := range dstu4145.AllParams() {
		f.Add(fuzzRawKey(f, params.Name))
	}
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		original := bytes.Clone(data)
		key, err := ParseRawKey(data)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, key)
			return
		}
		require.NotNil(t, key.Curve)
		require.Positive(t, key.D.Sign())
		require.Negative(t, key.D.Cmp(new(big.Int).SetBytes(key.Curve.N)))
		raw, err := MarshalRawKey(key)
		require.NoError(t, err)
		reread, err := ParseRawKey(raw)
		require.NoError(t, err)
		require.Equal(t, key.D, reread.D)
		require.True(t, key.Curve.EqualDomain(reread.Curve))
	})
}

func FuzzParseKey6(f *testing.F) {
	raw := fuzzRawKey(f, "DSTU_PB_257")
	salt := bytes.Repeat([]byte{0x53}, 32)
	legacy, err := MarshalKey6(raw, fuzzPassword, salt, 2, bytes.Repeat([]byte{0x49}, 8))
	require.NoError(f, err)
	modern, err := MarshalKey6Kalyna(raw, fuzzPassword, salt, 2, bytes.Repeat([]byte{0x49}, 32))
	require.NoError(f, err)
	f.Add(legacy)
	f.Add(modern)
	for _, seed := range [][]byte{legacy, modern} {
		key, err := ParseKey6(seed, fuzzPassword)
		require.NoError(f, err)
		require.Equal(f, int64(2), key.D.Int64())
	}
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 || !fuzzKey6Budget(data) {
			return
		}
		original := bytes.Clone(data)
		key, err := ParseKey6(data, fuzzPassword)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, key)
		} else {
			require.NotNil(t, key)
			require.Positive(t, key.D.Sign())
		}
	})
}

func FuzzParseJKSAuthenticated(f *testing.F) {
	encoded, err := os.ReadFile("testdata/jks-public-scalar.json")
	require.NoError(f, err)
	var fixture struct {
		Password string
		Store    []byte
	}
	require.NoError(f, json.Unmarshal(encoded, &fixture))
	f.Add(fixture.Store[:len(fixture.Store)-sha1.Size])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		// Reauthenticate arbitrary store bodies to reach entry/KeyProtector
		// parsing beyond the store-integrity gate, using a public password.
		h := sha1.New()
		h.Write(javaPassword(fixture.Password))
		h.Write([]byte("Mighty Aphrodite"))
		h.Write(body)
		store := append(bytes.Clone(body), h.Sum(nil)...)
		entries, parseErr := ParseJKS(store)
		if parseErr != nil {
			require.Nil(t, entries)
		}
		for _, entry := range entries {
			if !fuzzKey6Budget(entry.KeyDER) {
				return
			}
		}
		original := bytes.Clone(store)
		parsed, err := ParseJKSWithPassword(store, fixture.Password)
		require.Equal(t, original, store)
		if err != nil {
			require.Nil(t, parsed)
		} else {
			require.NotEmpty(t, parsed.Keys)
		}
		store[len(store)-1] ^= 1
		parsed, err = ParseJKSWithPassword(store, fixture.Password)
		require.Error(t, err)
		require.Nil(t, parsed)
	})
}
