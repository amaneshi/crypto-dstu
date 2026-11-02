package ua

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"crypto-dstu/internal/keystore"
	"github.com/stretchr/testify/require"
)

func TestProtectKey(t *testing.T) {
	key := mustGenerateKey(t)
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	for _, tc := range []struct {
		name     string
		data     []byte
		password string
	}{
		{"DER", raw, "test-password"},
		{"PEM", keystore.EncodePEM(raw, "PRIVATE KEY"), "Тест-password"},
		{"32 byte password", raw, string(bytes.Repeat([]byte{'K'}, 32))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protected, err := ProtectKey(tc.data, tc.password)
			require.NoError(t, err)
			box := NewBox()
			require.NoError(t, box.LoadKey(protected, tc.password))
			require.Len(t, box.keys, 1)
			require.Equal(t, key.Public(), box.keys[0].privateKey.Public())
			recovered, err := UnprotectKey(protected, tc.password, "der")
			require.NoError(t, err)
			require.Equal(t, raw, recovered)
			_, err = UnprotectKey(protected, "wrong-password", "der")
			require.Error(t, err)
		})
	}
	first, err := ProtectKey(raw, "test")
	require.NoError(t, err)
	second, err := ProtectKey(raw, "test")
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	// Compare both randomness fields, rather than accepting a changed IV alone.
	type aid struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue
	}
	parameters := func(encoded []byte) (salt, iv []byte) {
		var epki struct {
			Algorithm aid
			Data      []byte
		}
		_, err := asn1.Unmarshal(encoded, &epki)
		require.NoError(t, err)
		var p struct{ KDF, Cipher aid }
		_, err = asn1.Unmarshal(epki.Algorithm.Parameters.FullBytes, &p)
		require.NoError(t, err)
		var kdf struct {
			Salt       []byte
			Iterations int
			PRF        aid
		}
		_, err = asn1.Unmarshal(p.KDF.Parameters.FullBytes, &kdf)
		require.NoError(t, err)
		require.Equal(t, 10000, kdf.Iterations)
		var cipher struct{ IV []byte }
		_, err = asn1.Unmarshal(p.Cipher.Parameters.FullBytes, &cipher)
		require.NoError(t, err)
		require.Len(t, kdf.Salt, 32)
		require.Len(t, cipher.IV, 32)
		return kdf.Salt, cipher.IV
	}
	salt1, iv1 := parameters(first)
	salt2, iv2 := parameters(second)
	require.NotEqual(t, salt1, salt2)
	require.NotEqual(t, iv1, iv2)
}

func TestProtectKeyRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name, password string
		data           []byte
	}{
		{"empty password", "", nil},
		{"long password", string(bytes.Repeat([]byte{'K'}, 33)), nil},
		{"UTF8 byte limit", string(bytes.Repeat([]byte("К"), 17)), nil},
		{"trailing NUL", "password\x00", nil},
		{"missing key", "test", nil},
		{"not PKCS8", "test", []byte{0x30, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ProtectKey(tc.data, tc.password)
			require.Error(t, err)
			require.Nil(t, out)
		})
	}
}
