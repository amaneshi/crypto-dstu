package ua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/testtimestamp"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
)

func signOnce(t *testing.T, tsa *testTSA, opts *TimestampSignOptions) ([]byte, error) {
	t.Helper()
	key, err := OpenKey(tsa.signerKey, "", tsa.signer.Raw)
	require.NoError(t, err)
	signer, err := NewSigner(SignerOptions{Timestamp: opts})
	require.NoError(t, err)
	return signer.Sign(context.Background(), key, []byte("receipt"), SignOptions{NoTax: true})
}

// Without TSARoots a Signer still verifies everything about the token except
// the TSA's path to a trusted root.
func TestSignerUnanchoredTimestamp(t *testing.T) {
	tsa := newTestTSA(t)

	t.Run("valid token is accepted and attached", func(t *testing.T) {
		signed, err := signOnce(t, tsa, &TimestampSignOptions{URLs: []string{tsa.url}})
		require.NoError(t, err)
		// The token is genuine: a verifier that does trust the root accepts it.
		verifier := NewBox()
		verifier.caCerts = []*cert.Certificate{tsa.root}
		result, err := verifier.UnsignDocumentWithOptions(context.Background(), signed, nil,
			VerificationOptions{TimestampPolicy: TimestampRequireSignature, TSARoots: [][]byte{tsa.root.Raw}})
		require.NoError(t, err)
		require.True(t, result.Timestamps[0].Valid)
	})

	root, rootKey := testpki.Issue(t, "other root", nil, nil, testpki.CAExtensions(t))
	realTSA, realTSAKey := testpki.Issue(t, "TSA", root, rootKey, testtimestamp.Extensions(t))
	notTSA, notTSAKey := testpki.Issue(t, "not a TSA", root, rootKey, nil)
	for name, url := range map[string]string{
		"wrong imprint": serveTimestamps(t, realTSA, realTSAKey, func(i *tsp.TSTInfo) {
			i.MessageImprint.HashedMessage = append([]byte(nil), i.MessageImprint.HashedMessage...)
			i.MessageImprint.HashedMessage[0] ^= 0xff
		}, nil),
		"wrong nonce": serveTimestamps(t, realTSA, realTSAKey, func(i *tsp.TSTInfo) {
			i.Nonce = i.Nonce.Add(i.Nonce, i.Nonce)
		}, nil),
		"future time": serveTimestamps(t, realTSA, realTSAKey, func(i *tsp.TSTInfo) {
			i.GenTime = time.Now().Add(time.Hour)
		}, nil),
		"certificate without timestamping EKU": serveTimestamps(t, notTSA, notTSAKey, nil, nil),
		// The token ends with the TSA's signature value; flipping its last
		// byte keeps the DER valid but breaks the signature.
		"tampered TSA signature": serveTimestamps(t, realTSA, realTSAKey, nil, func(token []byte) {
			token[len(token)-1] ^= 0x01
		}),
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			signed, err := signOnce(t, tsa, &TimestampSignOptions{URLs: []string{url}})
			require.Error(t, err)
			require.Nil(t, signed, "no partial document")
			t.Log(err)
		})
	}
}

// AttemptTimeout lets a hung first TSA fall through to the next URL.
func TestSignerTimestampFailover(t *testing.T) {
	tsa := newTestTSA(t)
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select { // never answers; released at cleanup so Close can finish
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) }) // runs first: cleanups are LIFO
	refused := "http://127.0.0.1:1/"

	t.Run("refused then hung then good", func(t *testing.T) {
		started := time.Now()
		signed, err := signOnce(t, tsa, &TimestampSignOptions{
			TSARoots:       [][]byte{tsa.root.Raw},
			URLs:           []string{refused, hung.URL, tsa.url},
			AttemptTimeout: 300 * time.Millisecond,
		})
		require.NoError(t, err)
		require.NotEmpty(t, signed)
		require.Less(t, time.Since(started), 5*time.Second)
	})
	t.Run("all fail", func(t *testing.T) {
		signed, err := signOnce(t, tsa, &TimestampSignOptions{
			TSARoots:       [][]byte{tsa.root.Raw},
			URLs:           []string{refused, hung.URL},
			AttemptTimeout: 200 * time.Millisecond,
		})
		require.Error(t, err)
		require.Nil(t, signed)
	})
}

// Box honours TimestampSignOptions.URLs ahead of AddTSP, and still requires roots.
func TestBoxTimestampURLsAndRoots(t *testing.T) {
	tsa := newTestTSA(t)
	box := NewBox()
	require.NoError(t, box.LoadKey(tsa.signerKey, ""))
	require.NoError(t, box.AddCert(tsa.signer.Raw))
	box.AddTSP("http://127.0.0.1:1/") // would fail if it were used

	signed, err := box.SignDocumentWithContext(context.Background(), []byte("doc"), SignOptions{
		NoTax:     true,
		Timestamp: &TimestampSignOptions{TSARoots: [][]byte{tsa.root.Raw}, URLs: []string{tsa.url}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	_, err = box.SignDocumentWithContext(context.Background(), []byte("doc"), SignOptions{
		NoTax:     true,
		Timestamp: &TimestampSignOptions{URLs: []string{tsa.url}},
	})
	require.ErrorContains(t, err, "explicit TSA trust roots", "Box never verifies unanchored")
}
