//go:build integration

package interop_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/internal/testtimestamp"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITSignatureTimestampCompatibility(t *testing.T) {
	const password = "disposable-timestamp-test"
	generated := testiit.Invoke(t, testiit.Request{Operation: "generate", Password: password})
	require.True(t, generated.OK, generated.Error)
	pairs, err := keystore.ParsePKCS12(generated.Data, password)
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	key := pairs[0].PrivateKey
	signer := testiit.Certificate(t, key, false)
	tsaKey, err := dstu4145.GenerateKey(key.Curve)
	require.NoError(t, err)
	tsa := testiit.Certificate(t, tsaKey, true)
	for _, detached := range []bool{false, true} {
		t.Run(map[bool]string{false: "attached", true: "detached"}[detached], func(t *testing.T) {
			content := []byte("IIT CAdES-T independent interoperability control")
			plain, err := cms.Sign(content, key, signer, cms.SignOptions{Detached: detached})
			require.NoError(t, err)
			request := testiit.Request{Operation: "verify", Data: content, Signature: plain, Detached: detached, Certificates: [][]byte{signer.Raw, tsa.Raw}}
			baseline := testiit.Invoke(t, request)
			require.True(t, baseline.OK, baseline.Error)
			require.Equal(t, content, baseline.Data)
			request.RequireTimestamp = true
			require.False(t, testiit.Invoke(t, request).OK, "claimed CMS signingTime cannot satisfy timestamp policy")
			message, err := cms.ParseSigned(plain)
			require.NoError(t, err)
			signature, err := message.SignatureBytes(0)
			require.NoError(t, err)
			token := testtimestamp.Token(t, signature, tsa, tsaKey, nil)
			_, err = tsp.VerifySignatureTimestamp(token, signature, []*cert.Certificate{tsa}, time.Now())
			require.NoError(t, err)
			timestamped, err := cms.AttachSignatureTimestamp(plain, token)
			require.NoError(t, err)
			request.Signature = timestamped
			result := testiit.Invoke(t, request)
			require.True(t, result.OK, result.Error)
			require.Equal(t, content, result.Data)
			parsed, err := cms.ParseSigned(token)
			require.NoError(t, err)
			tokenSignature, err := parsed.SignatureBytes(0)
			require.NoError(t, err)
			alteredToken := append([]byte(nil), token...)
			position := bytes.Index(alteredToken, tokenSignature)
			require.GreaterOrEqual(t, position, 0)
			alteredToken[position] ^= 1
			wrongImprint := testtimestamp.Token(t, content, tsa, tsaKey, nil)
			for _, tc := range []struct {
				name  string
				token []byte
			}{{"altered token signature", alteredToken}, {"valid token for wrong imprint", wrongImprint}} {
				t.Run(tc.name, func(t *testing.T) {
					_, err = tsp.VerifySignatureTimestamp(tc.token, signature, []*cert.Certificate{tsa}, time.Now())
					require.Error(t, err)
					request.Signature, err = cms.AttachSignatureTimestamp(plain, tc.token)
					require.NoError(t, err)
					result := testiit.Invoke(t, request)
					require.False(t, result.OK, "IIT accepted %s", tc.name)
					require.Empty(t, result.Data)
				})
			}
		})
	}
}
