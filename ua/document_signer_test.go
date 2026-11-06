package ua

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

func mustRawKey(t *testing.T, key *dstu4145.PrivateKey) []byte {
	t.Helper()
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	return raw
}

func TestOpenKey(t *testing.T) {
	tsa := newTestTSA(t)
	wantKeyID := hex.EncodeToString(cert.KeyID(tsa.signer))

	t.Run("PFX with embedded certificate", func(t *testing.T) {
		pfx, err := ProtectPKCS12(tsa.signerKey, [][]byte{tsa.signer.Raw}, "secret")
		require.NoError(t, err)
		key, err := OpenKey(pfx, "secret")
		require.NoError(t, err)
		info := key.Info()
		require.Equal(t, wantKeyID, info.KeyID)
		require.Equal(t, tsa.signer.Raw, key.Certificate())

		_, err = OpenKey(pfx, "wrong")
		require.Error(t, err)
	})
	t.Run("Key-6 needs the certificate supplied", func(t *testing.T) {
		key6, err := ProtectKey(tsa.signerKey, "secret")
		require.NoError(t, err)
		_, err = OpenKey(key6, "secret")
		require.ErrorContains(t, err, "no signing certificate")

		key, err := OpenKey(key6, "secret", tsa.signer.Raw)
		require.NoError(t, err)
		require.Equal(t, wantKeyID, key.Info().KeyID)
	})
	t.Run("role", func(t *testing.T) {
		_, err := OpenKeyByRole(tsa.signerKey, "", "", tsa.signer.Raw)
		require.Error(t, err)
		_, err = OpenKeyByRole(tsa.signerKey, "", "stamp", tsa.signer.Raw)
		require.Error(t, err, "the test signer is not a stamp key")
	})
	t.Run("garbage", func(t *testing.T) {
		_, err := OpenKey([]byte("not a key"), "secret")
		require.Error(t, err)
	})
}

func TestNewSignerValidation(t *testing.T) {
	tsa := newTestTSA(t)
	roots := [][]byte{tsa.root.Raw}
	for name, opts := range map[string]SignerOptions{
		"invalid root":             {Timestamp: &TimestampSignOptions{TSARoots: [][]byte{{0x30, 0x00}}}},
		"invalid URL":              {Timestamp: &TimestampSignOptions{TSARoots: roots, URLs: []string{"ftp://tsa"}}},
		"URL without host":         {Timestamp: &TimestampSignOptions{URLs: []string{"http://"}}},
		"negative attempt timeout": {Timestamp: &TimestampSignOptions{AttemptTimeout: -time.Second}},
		"verification policy in creation options": {Timestamp: &TimestampSignOptions{
			TSARoots: roots, RevocationOptions: VerificationOptions{TimestampPolicy: TimestampRequireSignature},
		}},
		"revocation without roots": {Timestamp: &TimestampSignOptions{
			RevocationOptions: VerificationOptions{Revocation: RevocationRequireOCSP},
		}},
	} {
		_, err := NewSigner(opts)
		require.Error(t, err, name)
	}

	none, err := NewSigner(SignerOptions{})
	require.NoError(t, err)
	require.Nil(t, none.timestamp, "nil Timestamp: no timestamps at all")

	anchored, err := NewSigner(SignerOptions{Timestamp: &TimestampSignOptions{TSARoots: roots}})
	require.NoError(t, err)
	require.Equal(t, []string{DefaultTSPURL}, anchored.timestamp.URLs, "empty URLs: DefaultTSPURL")
	require.False(t, anchored.timestamp.unanchored)

	unanchored, err := NewSigner(SignerOptions{Timestamp: &TimestampSignOptions{}})
	require.NoError(t, err)
	require.True(t, unanchored.timestamp.unanchored, "empty TSARoots: unanchored")
	require.Equal(t, []string{DefaultTSPURL}, unanchored.timestamp.URLs)

	// NewSigner copies roots and URLs: later changes by the caller have no effect.
	callerRoots := [][]byte{append([]byte(nil), tsa.root.Raw...)}
	callerURLs := []string{tsa.url}
	signer, err := NewSigner(SignerOptions{Timestamp: &TimestampSignOptions{TSARoots: callerRoots, URLs: callerURLs}})
	require.NoError(t, err)
	callerRoots[0][0] ^= 0xff
	callerURLs[0] = "http://127.0.0.1:1/"
	key, err := OpenKey(tsa.signerKey, "", tsa.signer.Raw)
	require.NoError(t, err)
	_, err = signer.Sign(context.Background(), key, []byte("doc"), SignOptions{NoTax: true})
	require.NoError(t, err)
}

func TestSignerSign(t *testing.T) {
	tsa := newTestTSA(t)
	key, openErr := OpenKey(tsa.signerKey, "", tsa.signer.Raw)
	require.NoError(t, openErr)
	verifier := NewBox()
	verifier.caCerts = []*cert.Certificate{tsa.root}

	t.Run("without timestamp", func(t *testing.T) {
		signer, nerr := NewSigner(SignerOptions{})
		require.NoError(t, nerr)
		signed, err := signer.Sign(context.Background(), key, []byte("receipt"), SignOptions{NoTax: true})
		require.NoError(t, err)
		result, err := verifier.UnsignDocument(signed)
		require.NoError(t, err)
		require.Equal(t, []byte("receipt"), result.Content)
	})
	t.Run("with verified signature timestamp", func(t *testing.T) {
		signer, nerr := NewSigner(SignerOptions{
			Timestamp: &TimestampSignOptions{TSARoots: [][]byte{tsa.root.Raw}, URLs: []string{tsa.url}},
		})
		require.NoError(t, nerr)
		signed, err := signer.Sign(context.Background(), key, []byte("receipt"), SignOptions{NoTax: true})
		require.NoError(t, err)
		result, err := verifier.UnsignDocumentWithOptions(context.Background(), signed, nil,
			VerificationOptions{TimestampPolicy: TimestampRequireSignature, TSARoots: [][]byte{tsa.root.Raw}})
		require.NoError(t, err)
		require.Len(t, result.Timestamps, 1)
		require.True(t, result.Timestamps[0].Valid)
	})
	t.Run("TSA down returns no document", func(t *testing.T) {
		signer, nerr := NewSigner(SignerOptions{
			Timestamp: &TimestampSignOptions{TSARoots: [][]byte{tsa.root.Raw}, URLs: []string{"http://127.0.0.1:1/"}},
		})
		require.NoError(t, nerr)
		signed, err := signer.Sign(context.Background(), key, []byte("receipt"), SignOptions{NoTax: true})
		require.Error(t, err)
		require.Nil(t, signed)
	})
	t.Run("misuse", func(t *testing.T) {
		signer, nerr := NewSigner(SignerOptions{})
		require.NoError(t, nerr)
		_, err := signer.Sign(context.Background(), nil, []byte("x"), SignOptions{})
		require.Error(t, err)
		_, err = signer.Sign(context.Background(), key, []byte("x"), SignOptions{Timestamp: &TimestampSignOptions{}})
		require.ErrorContains(t, err, "configured on the Signer")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = signer.Sign(ctx, key, []byte("x"), SignOptions{})
		require.ErrorIs(t, err, context.Canceled)
	})
}

// Signing must not depend on the signer certificate's validity period: a key
// whose certificate has expired can still be required (for example, to close a
// fiscal shift that the same key opened). Validity is left to the verifier.
func TestSignerSignsWithExpiredCertificate(t *testing.T) {
	tsa := newTestTSA(t)
	root, rootKey := testpki.Issue(t, "expired-root", nil, nil, testpki.CAExtensions(t))
	expired, key := testpki.IssueWithOptions(t, "expired signer", root, rootKey, testpki.CertificateOptions{
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	})
	opened, err := OpenKey(mustRawKey(t, key), "", expired.Raw)
	require.NoError(t, err)
	require.True(t, opened.Info().NotAfter.Before(time.Now()))

	plain, err := NewSigner(SignerOptions{})
	require.NoError(t, err)
	stamped, err := NewSigner(SignerOptions{
		Timestamp: &TimestampSignOptions{TSARoots: [][]byte{tsa.root.Raw}, URLs: []string{tsa.url}},
	})
	require.NoError(t, err)
	for name, signer := range map[string]*Signer{"plain": plain, "timestamped": stamped} {
		signed, signErr := signer.Sign(context.Background(), opened, []byte("close shift"), SignOptions{NoTax: true})
		require.NoError(t, signErr, name)
		message, parseErr := cms.ParseSigned(signed)
		require.NoError(t, parseErr, name)
		require.Len(t, message.Signers, 1, name)
	}
}
