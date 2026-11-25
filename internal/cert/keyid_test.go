package cert

import (
	"encoding/asn1"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amaneshi/crypto-dstu/internal/oid"
)

// SKI prefixes are taken from the certificates' extensions, parsed by this
// package; the full value is checked in ua.TestSigningCertInfo.
func TestKeyIDIsSubjectKeyIdentifier(t *testing.T) {
	tests := []struct {
		path string
		ski  string
	}{
		{"../ocsp/testdata/czo-2025/subject.cer", "b756205e"},
	}
	for _, tt := range tests {
		t.Run(filepath.Base(filepath.Dir(tt.path)), func(t *testing.T) {
			c := loadTestCert(t, tt.path)
			assert.True(t, len(c.KeyID()) > 0)
			assert.Equal(t, tt.ski, hex.EncodeToString(c.KeyID())[:len(tt.ski)])
		})
	}
}

func TestKeyIDEdgeCases(t *testing.T) {
	enc := func(b []byte) []byte {
		v, err := asn1.Marshal(b)
		require.NoError(t, err)
		return v
	}
	ext := func(v []byte) Extension { return Extension{Id: oid.OIDExtSubjectKeyID, Value: v} }

	assert.Nil(t, (&Certificate{}).KeyID(), "absent")
	assert.Equal(t, []byte{1, 2}, (&Certificate{Extensions: []Extension{ext(enc([]byte{1, 2}))}}).KeyID())
	assert.Nil(t, (&Certificate{Extensions: []Extension{ext(enc([]byte{1})), ext(enc([]byte{1}))}}).KeyID(), "duplicate")
	assert.Nil(t, (&Certificate{Extensions: []Extension{ext([]byte{0xff})}}).KeyID(), "malformed")
	assert.Nil(t, (&Certificate{Extensions: []Extension{ext(append(enc([]byte{1}), 0))}}).KeyID(), "trailing data")
	assert.Nil(t, (&Certificate{Extensions: []Extension{ext(enc(nil))}}).KeyID(), "empty")
}

func loadTestCert(t *testing.T, path string) *Certificate {
	t.Helper()
	der, err := os.ReadFile(filepath.FromSlash(path))
	require.NoError(t, err)
	c, err := ParseCertificate(der)
	require.NoError(t, err)
	return c
}
