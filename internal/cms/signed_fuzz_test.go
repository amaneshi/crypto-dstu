package cms

import (
	"bytes"
	"encoding/asn1"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	czo "github.com/amaneshi/crypto-dstu/testdata/czo"
	"github.com/stretchr/testify/require"
)

func FuzzParseAndVerifySigned(f *testing.F) {
	certificate, key := testpki.Issue(f, "Disposable CMS fuzz signer", nil, nil, nil)
	content := []byte("CMS fuzz content\x00\xff")
	for _, digest := range []asn1.ObjectIdentifier{oid.GOST34311, oid.Kupyna256, oid.Kupyna512} {
		for _, detached := range []bool{false, true} {
			seed, err := Sign(content, key, certificate, SignOptions{Detached: detached, DigestAlgorithm: digest})
			require.NoError(f, err)
			message, err := VerifySignedRaw(seed, content, nil)
			require.NoError(f, err)
			require.True(f, message.Signers[0].Valid)
			f.Add(seed, content)
		}
	}
	for _, profile := range []string{"DSTU", "DSTU-7564"} {
		seed, err := os.ReadFile(czo.Path("cades/" + profile + "/enveloped/CAdES-BES/test.txt.p7s"))
		require.NoError(f, err)
		f.Add(seed, []byte{})
	}
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x30, 0}, []byte{})
	f.Fuzz(func(t *testing.T, data, detached []byte) {
		if len(data) > 64<<10 || len(detached) > 64<<10 {
			return
		}
		original, originalDetached := bytes.Clone(data), bytes.Clone(detached)
		message, err := ParseSigned(data)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, message)
			return
		}
		for _, signer := range message.Signers {
			require.False(t, signer.Valid, "parsing alone authenticated a signer")
		}
		withJunk, err := ParseSigned(append(bytes.Clone(data), 0))
		require.Error(t, err)
		require.Nil(t, withJunk)
		content := message.Content
		if content == nil {
			content = detached
		}
		// Nil roots request mathematical checks only; these fixtures establish
		// no identity trust and trigger no certificate/timestamp network calls.
		if VerifySigned(message, content, nil) == nil {
			require.NotEmpty(t, message.Signers)
			for _, signer := range message.Signers {
				require.True(t, signer.Valid)
				require.NoError(t, signer.Error)
			}
			require.Error(t, VerifySigned(message, append(bytes.Clone(content), 1), nil))
			for _, signer := range message.Signers {
				require.False(t, signer.Valid, "failed reverification retained an authenticated flag")
			}
		}
		require.Equal(t, original, data, "verification changed the caller's DER")
		require.Equal(t, originalDetached, detached, "verification changed detached content")
	})
}
