package ua

import (
	"context"
	"testing"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/testpki"
	"crypto-dstu/internal/testtimestamp"
	"github.com/stretchr/testify/require"
)

func TestSignatureTimestampControlsContentRelease(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	signer, key := testpki.Issue(t, "signer", root, rootKey, nil)
	tsa, tsaKey := testpki.Issue(t, "TSA", root, rootKey, testtimestamp.Extensions(t))
	box := NewBox()
	box.caCerts = []*cert.Certificate{root}
	box.keys = []*keyEntry{{privateKey: key, signCert: signer}}
	content := []byte("timestamp protected receipt")
	signed, err := box.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	message, err := cms.ParseSigned(signed)
	require.NoError(t, err)
	signature, err := message.SignatureBytes(0)
	require.NoError(t, err)
	token := testtimestamp.Token(t, signature, tsa, tsaKey, nil)
	timestamped := testtimestamp.Attach(t, signed, token)
	wrong := testtimestamp.Attach(t, signed, testtimestamp.Token(t, content, tsa, tsaKey, nil))
	leafOCSP := testpki.OCSP(t, signer, root, root, rootKey, testpki.OCSPOptions{})
	tsaOCSP := testpki.OCSP(t, tsa, root, root, rootKey, testpki.OCSPOptions{})
	revoked := testpki.OCSP(t, tsa, root, root, rootKey, testpki.OCSPOptions{Status: 1})
	for _, tc := range []struct {
		name       string
		data       []byte
		policy     TimestampPolicy
		revocation RevocationPolicy
		responses  [][]byte
		fail       bool
		timestamp  bool
	}{
		{"default ignores timestamp", wrong, TimestampIgnore, RevocationDisabled, nil, false, false},
		{"optional absent", signed, TimestampVerifyIfPresent, RevocationDisabled, nil, false, false},
		{"required absent", signed, TimestampRequireSignature, RevocationDisabled, nil, true, false},
		{"required valid", timestamped, TimestampRequireSignature, RevocationDisabled, nil, false, true},
		{"wrong signature binding", wrong, TimestampRequireSignature, RevocationDisabled, nil, true, false},
		{"optional invalid", wrong, TimestampVerifyIfPresent, RevocationDisabled, nil, true, false},
		{"TSA revocation missing", timestamped, TimestampRequireSignature, RevocationRequireOCSP, [][]byte{leafOCSP}, true, false},
		{"TSA revoked", timestamped, TimestampRequireSignature, RevocationRequireOCSP, [][]byte{leafOCSP, revoked}, true, false},
		{"TSA good", timestamped, TimestampRequireSignature, RevocationRequireOCSP, [][]byte{leafOCSP, tsaOCSP}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := VerificationOptions{TimestampPolicy: tc.policy, Revocation: tc.revocation, OCSPResponses: tc.responses}
			if tc.policy != TimestampIgnore {
				options.TSARoots = [][]byte{root.Raw}
			}
			result, err := box.UnsignDocumentWithOptions(context.Background(), tc.data, nil, options)
			require.NotNil(t, result)
			if tc.fail {
				require.Error(t, err)
				require.Empty(t, result.Content)
			} else {
				require.NoError(t, err)
				require.Equal(t, content, result.Content)
			}
			if tc.timestamp {
				require.Len(t, result.Timestamps, 1)
				require.True(t, result.Timestamps[0].Valid)
				require.False(t, result.Timestamps[0].Time.IsZero())
				require.NotNil(t, result.Timestamps[0].TSA)
			} else {
				for _, ts := range result.Timestamps {
					require.False(t, ts.Valid)
					require.True(t, ts.Time.IsZero())
				}
			}
		})
	}
	for _, options := range []VerificationOptions{{TimestampPolicy: TimestampRequireSignature}, {TSARoots: [][]byte{root.Raw}}, {TimestampPolicy: 99}} {
		_, err := options.normalized()
		require.Error(t, err)
	}
}
