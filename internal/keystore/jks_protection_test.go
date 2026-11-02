package keystore

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJavaJKSIndependentVector(t *testing.T) {
	encoded, err := os.ReadFile("testdata/jks-public-scalar.json")
	require.NoError(t, err)
	var fixture struct {
		Password         string
		Store, Plaintext []byte
	}
	require.NoError(t, json.Unmarshal(encoded, &fixture))
	require.NoError(t, verifyJKSDigest(fixture.Store, fixture.Password))
	entries, err := ParseJKS(fixture.Store)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	plain, err := decryptJavaKey(entries[0].KeyDER, fixture.Password)
	require.NoError(t, err)
	require.Equal(t, fixture.Plaintext, plain)
	parsed, err := Parse(fixture.Store, fixture.Password)
	require.NoError(t, err)
	require.Len(t, parsed.Keys, 1)
	require.Equal(t, int64(1), parsed.Keys[0].D.Int64())
	require.Error(t, verifyJKSDigest(fixture.Store, "wrong"))
	plain, err = decryptJavaKey(entries[0].KeyDER, "wrong")
	require.Error(t, err)
	require.Nil(t, plain)
	for i := range fixture.Store {
		bad := bytes.Clone(fixture.Store)
		bad[i] ^= 1
		require.Error(t, verifyJKSDigest(bad, fixture.Password), "byte %d", i)
	}
	for i := range entries[0].KeyDER {
		bad := bytes.Clone(entries[0].KeyDER)
		bad[i] ^= 1
		plain, err = decryptJavaKey(bad, fixture.Password)
		// The algorithm's optional NULL does not affect key protection.
		if err == nil {
			require.Equal(t, fixture.Plaintext, plain)
		} else {
			require.Nil(t, plain)
		}
	}
}

func TestJavaPasswordUTF16(t *testing.T) {
	require.Equal(t, []byte{0, 0x41, 4, 0x1a, 0xd8, 0x3d, 0xde, 0}, javaPassword("AК😀"))
}
