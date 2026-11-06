package cert

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The expected key IDs were computed independently by jkurwa 1.21.0
// (Certificate.from_asn1(der).pubkey.keyid(gost89.compat.algos())), the
// library behind dstucrypt/agent. czo-2025 is the case where the key ID differs
// from the certificate's SubjectKeyIdentifier (b756205e…).
func TestKeyIDMatchesJkurwa(t *testing.T) {
	tests := []struct {
		path  string
		keyID string
	}{
		{"../ocsp/testdata/czo-2025/subject.cer", "e1bcc73d9a160a4df8e66a4e90333f695f3dd333674d1bc67d09ef70ab5d788e"},
		{"../ocsp/testdata/czo-2021/subject.cer", "55795617f3f16df62ef10d07b1ee77192be756af94efc426b845836f2994ac1b"},
		{
			"../interop/testdata/iit-czo-cades-t/signer.cer",
			"f4570fe8666cd12ebb850b01563d9967ac50c760764da9ea7462ecc1a15ab40b",
		},
		{
			"../interop/testdata/iit-czo-cades-t/tsa.cer",
			"2b28c9374f6ff5372d2d73f2b851f652d76698b7038fa0e4502ff31a3ffd20f2",
		},
		{"../tsp/testdata/czo-live/root.cer", "4ff5754acbe987791800ea40b0882894418c7b73d254711f6e53d34629775a76"},
	}
	for _, tt := range tests {
		t.Run(filepath.Base(filepath.Dir(tt.path))+"/"+filepath.Base(tt.path), func(t *testing.T) {
			c := loadTestCert(t, tt.path)
			assert.Equal(t, tt.keyID, hex.EncodeToString(KeyID(c)))
		})
	}
}

func TestKeyIDEmptyPublicKey(t *testing.T) {
	assert.Nil(t, KeyID(&Certificate{}))
}

func loadTestCert(t *testing.T, path string) *Certificate {
	t.Helper()
	der, err := os.ReadFile(filepath.FromSlash(path))
	require.NoError(t, err)
	c, err := ParseCertificate(der)
	require.NoError(t, err)
	return c
}
