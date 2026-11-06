package ua

import (
	"context"
	"encoding/asn1"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/testtimestamp"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
)

// testTSA is a local RFC 3161 server issuing tokens signed by a TSA under root.
type testTSA struct {
	root      *cert.Certificate
	signer    *cert.Certificate
	signerKey []byte // raw PKCS#8 DER of the document signer's key
	url       string
}

func newTestTSA(t *testing.T) *testTSA {
	t.Helper()
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	signer, key := testpki.Issue(t, "signer", root, rootKey, nil)
	tsa, tsaKey := testpki.Issue(t, "TSA", root, rootKey, testtimestamp.Extensions(t))
	return &testTSA{
		root: root, signer: signer, signerKey: mustRawKey(t, key),
		url: serveTimestamps(t, tsa, tsaKey, nil, nil),
	}
}

// serveTimestamps runs an RFC 3161 server whose tokens are signed by tsa/tsaKey.
// change, when set, alters each TSTInfo after the request's imprint and nonce
// are copied in; tamper, when set, alters the finished token bytes. Tests use
// them to produce tokens that must be rejected.
func serveTimestamps(
	t *testing.T, tsa *cert.Certificate, tsaKey *dstu4145.PrivateKey,
	change func(*tsp.TSTInfo), tamper func([]byte),
) string {
	t.Helper()
	var tokenMu sync.Mutex // testtimestamp.Token uses the test's require helpers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var request tsp.Request
		if _, err = asn1.Unmarshal(body, &request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tokenMu.Lock()
		token := testtimestamp.Token(t, nil, tsa, tsaKey, func(i *tsp.TSTInfo) {
			i.MessageImprint = request.MessageImprint
			i.Nonce = request.Nonce
			if change != nil {
				change(i)
			}
		})
		tokenMu.Unlock()
		if tamper != nil {
			tamper(token)
		}
		response, err := asn1.Marshal(tsp.Response{
			Status:         tsp.PKIStatusInfo{Status: tsp.StatusGranted},
			TimeStampToken: asn1.RawValue{FullBytes: token},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(response)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// verifyConcurrently runs sign from 8 goroutines (32 documents, half of them
// timestamped) and verifies each result. Run with -race.
func verifyConcurrently(
	t *testing.T,
	root *cert.Certificate,
	sign func(content []byte, timestamp bool) ([]byte, error),
) {
	t.Helper()
	verifier := NewBox()
	verifier.caCerts = []*cert.Certificate{root}
	const workers, rounds = 8, 4
	errs := make(chan error, workers*rounds)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for r := range rounds {
				content := []byte{byte(w), byte(r), 'x'}
				timestamp := (w+r)%2 == 0
				signed, err := sign(content, timestamp)
				if err != nil {
					errs <- err
					continue
				}
				options := VerificationOptions{}
				if timestamp {
					options = VerificationOptions{
						TimestampPolicy: TimestampRequireSignature,
						TSARoots:        [][]byte{root.Raw},
					}
				}
				verified, err := verifier.UnsignDocumentWithOptions(context.Background(), signed, nil, options)
				if err != nil {
					errs <- err
					continue
				}
				if string(verified.Content) != string(content) {
					errs <- io.ErrUnexpectedEOF
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

// A loaded Box must be usable concurrently for signing (see the Box doc comment).
func TestConcurrentSigningOnOneBox(t *testing.T) {
	tsa := newTestTSA(t)
	box := NewBox()
	require.NoError(t, box.LoadKey(tsa.signerKey, ""))
	require.NoError(t, box.AddCert(tsa.signer.Raw))
	box.AddTSP(tsa.url)
	verifyConcurrently(t, tsa.root, func(content []byte, timestamp bool) ([]byte, error) {
		opts := SignOptions{NoTax: true}
		if timestamp {
			opts.Timestamp = &TimestampSignOptions{TSARoots: [][]byte{tsa.root.Raw}}
		}
		return box.SignDocumentWithContext(context.Background(), content, opts)
	})
}

// One Key shared by two Signers (with and without timestamps) from many goroutines.
func TestConcurrentSigningWithSharedKeyAndSigner(t *testing.T) {
	tsa := newTestTSA(t)
	key, err := OpenKey(tsa.signerKey, "", tsa.signer.Raw)
	require.NoError(t, err)
	plain, err := NewSigner(SignerOptions{})
	require.NoError(t, err)
	stamped, err := NewSigner(SignerOptions{
		Timestamp: &TimestampSignOptions{TSARoots: [][]byte{tsa.root.Raw}, URLs: []string{tsa.url}},
	})
	require.NoError(t, err)
	verifyConcurrently(t, tsa.root, func(content []byte, timestamp bool) ([]byte, error) {
		signer := plain
		if timestamp {
			signer = stamped
		}
		return signer.Sign(context.Background(), key, content, SignOptions{NoTax: true})
	})
}
