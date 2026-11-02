package cms_test

import (
	"bytes"
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/stretchr/testify/require"
)

// These disposable-key vectors were signed and encoded by the native IIT SDK.
// Verify mathematically without current-time trust: the fixture certificate is
// short-lived, and this regression test does not establish production trust.
func TestCapturedNativeKupyna512(t *testing.T) {
	directory := filepath.Join("..", "interop", "testdata", "iit-kupyna512")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(directory, name))
		require.NoError(t, err)
		return data
	}
	content, certificate := read("content.bin"), read("signer.cer")
	for _, mode := range []string{"attached", "detached"} {
		t.Run(mode, func(t *testing.T) {
			der := read(mode + ".cms")
			require.Equal(t, oid.Kupyna512, testiit.SignerDigest(t, der))
			require.Equal(t, []asn1.ObjectIdentifier{oid.Kupyna512}, testiit.DigestSet(t, der))
			require.Equal(t, mode == "attached", testiit.HasEmbeddedContent(t, der))
			message, err := cms.VerifySignedRaw(der, content, nil)
			require.NoError(t, err)
			require.Len(t, message.Signers, 1)
			require.True(t, message.Signers[0].Valid)
			require.Equal(t, certificate, message.Signers[0].Certificate.Raw)
			changed := bytes.Repeat([]byte{'X'}, len(content))
			altered := der
			if mode == "attached" {
				require.Equal(t, 1, bytes.Count(der, content))
				altered = bytes.Replace(der, content, changed, 1)
			}
			_, err = cms.VerifySignedRaw(altered, changed, nil)
			require.Error(t, err)
			signature, err := message.SignatureBytes(0)
			require.NoError(t, err)
			require.Equal(t, 1, bytes.Count(der, signature))
			corrupt := bytes.Clone(signature)
			corrupt[0] ^= 1
			_, err = cms.VerifySignedRaw(bytes.Replace(der, signature, corrupt, 1), content, nil)
			require.Error(t, err)
		})
	}
}
