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
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
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

	pub := []byte{4, 33, 1, 2, 3}
	h := kupyna.New256()
	h.Write(pub)
	want := h.Sum(nil)

	assert.Nil(t, (&Certificate{}).KeyID(), "no extension and no key bytes")
	assert.Equal(t, want, (&Certificate{SubjectPublicKeyBytes: pub}).KeyID(), "absent: Kupyna-256 fallback")
	assert.Nil(t, (&Certificate{SubjectPublicKeyBytes: pub}).SubjectKeyID(), "SubjectKeyID never falls back")

	withExt := func(exts ...Extension) *Certificate {
		return &Certificate{SubjectPublicKeyBytes: pub, Extensions: exts}
	}
	good := withExt(ext(enc([]byte{1, 2})))
	assert.Equal(t, []byte{1, 2}, good.KeyID())
	assert.Equal(t, []byte{1, 2}, good.SubjectKeyID())
	for name, c := range map[string]*Certificate{
		"duplicate":     withExt(ext(enc([]byte{1})), ext(enc([]byte{1}))),
		"malformed":     withExt(ext([]byte{0xff})),
		"trailing data": withExt(ext(append(enc([]byte{1}), 0))),
		"empty":         withExt(ext(enc(nil))),
	} {
		assert.Nil(t, c.KeyID(), name+": no fallback for a corrupt extension")
		assert.Nil(t, c.SubjectKeyID(), name)
	}
}

func loadTestCert(t *testing.T, path string) *Certificate {
	t.Helper()
	der, err := os.ReadFile(filepath.FromSlash(path))
	require.NoError(t, err)
	c, err := ParseCertificate(der)
	require.NoError(t, err)
	return c
}
