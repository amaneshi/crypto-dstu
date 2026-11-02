package ua

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/testtimestamp"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestCreateVerifiedSignatureTimestamp(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	signer, key := testpki.Issue(t, "signer", root, rootKey, nil)
	tsa, tsaKey := testpki.Issue(t, "TSA", root, rootKey, testtimestamp.Extensions(t))
	box := NewBox()
	box.caCerts = []*cert.Certificate{root}
	box.keys = []*keyEntry{{privateKey: key, signCert: signer, cryptCert: signer}}
	fetch := func(ctx context.Context, input TimestampRequest) ([]byte, error) {
		var request tsp.Request
		rest, err := asn1.Unmarshal(input.DER, &request)
		require.NoError(t, err)
		require.Empty(t, rest)
		require.True(t, request.CertReq)
		require.Positive(t, request.Nonce.Sign())
		token := testtimestamp.Token(t, nil, tsa, tsaKey, func(i *tsp.TSTInfo) { i.MessageImprint = request.MessageImprint; i.Nonce = request.Nonce })
		response, err := asn1.Marshal(tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: token}})
		require.NoError(t, err)
		return response, nil
	}
	for _, tc := range []struct {
		name            string
		detached, noTax bool
	}{{"attached raw", false, true}, {"detached raw", true, true}, {"attached transport", false, false}, {"detached transport", true, false}, {"empty attached", false, true}, {"empty detached", true, true}, {"content and signature timestamps", false, true}, {"detached content and signature timestamps", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte("protected input")
			if tc.name == "empty attached" || tc.name == "empty detached" {
				content = []byte{}
			}
			options := SignOptions{NoTax: tc.noTax, Detached: tc.detached, Timestamp: &TimestampSignOptions{TSARoots: [][]byte{root.Raw}, Fetch: fetch}}
			options.Timestamp.IncludeContentTimestamp = tc.name == "content and signature timestamps" || tc.name == "detached content and signature timestamps"
			signed, err := box.SignDocumentWithContext(context.Background(), content, options)
			require.NoError(t, err)
			var detached []byte
			if tc.detached {
				detached = content
			}
			verified, err := box.UnsignDocumentWithOptions(context.Background(), signed, detached, VerificationOptions{TimestampPolicy: TimestampRequireSignature, TSARoots: [][]byte{root.Raw}})
			require.NoError(t, err)
			require.Equal(t, content, verified.Content)
			require.Len(t, verified.Timestamps, 1)
			require.True(t, verified.Timestamps[0].Valid)
			if options.Timestamp.IncludeContentTimestamp {
				message, err := cms.ParseSigned(signed)
				require.NoError(t, err)
				tokens, err := message.ContentTimestampTokens(0)
				require.NoError(t, err)
				require.Len(t, tokens, 1)
				hash, err := tsp.HashData(content, asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 1})
				require.NoError(t, err)
				_, err = tsp.VerifyToken(tokens[0], hash, nil, []*cert.Certificate{root})
				require.NoError(t, err)
				_, err = tsp.VerifyToken(tokens[0], []byte("wrong imprint"), nil, []*cert.Certificate{root})
				require.Error(t, err)
			}
		})
	}
	t.Run("sign timestamp encrypt", func(t *testing.T) {
		content := []byte("encrypted timestamped document")
		for _, raw := range []bool{false, true} {
			encrypted, err := box.SignAndEncryptWithContext(context.Background(), content, signer.Raw, SignOptions{NoTax: raw, Timestamp: &TimestampSignOptions{TSARoots: [][]byte{root.Raw}, Fetch: fetch}})
			require.NoError(t, err)
			signed, err := box.DecryptDocument(encrypted)
			require.NoError(t, err)
			verified, err := box.UnsignDocumentWithOptions(context.Background(), signed, nil, VerificationOptions{TimestampPolicy: TimestampRequireSignature, TSARoots: [][]byte{root.Raw}})
			require.NoError(t, err)
			require.Equal(t, content, verified.Content)
			require.True(t, verified.Timestamps[0].Valid)
		}
	})
	t.Run("callback cannot mutate signed input", func(t *testing.T) {
		content := []byte("original input")
		expected := bytes.Clone(content)
		signed, err := box.SignDocument(content, SignOptions{Timestamp: &TimestampSignOptions{TSARoots: [][]byte{root.Raw}, Fetch: func(ctx context.Context, input TimestampRequest) ([]byte, error) {
			for i := range content {
				content[i] = 'X'
			}
			return fetch(ctx, input)
		}}})
		require.NoError(t, err)
		result, err := box.UnsignDocumentWithOptions(context.Background(), signed, nil, VerificationOptions{TimestampPolicy: TimestampRequireSignature, TSARoots: [][]byte{root.Raw}})
		require.NoError(t, err)
		require.Equal(t, expected, result.Content)
	})
	for _, tc := range []struct {
		name  string
		fetch func(context.Context, TimestampRequest) ([]byte, error)
	}{
		{"unavailable", func(context.Context, TimestampRequest) ([]byte, error) { return nil, errors.New("unavailable") }},
		{"malformed response", func(context.Context, TimestampRequest) ([]byte, error) { return []byte{0x30, 0}, nil }},
		{"nonce mismatch", func(ctx context.Context, input TimestampRequest) ([]byte, error) {
			var req tsp.Request
			_, err := asn1.Unmarshal(input.DER, &req)
			require.NoError(t, err)
			token := testtimestamp.Token(t, nil, tsa, tsaKey, func(i *tsp.TSTInfo) {
				i.MessageImprint = req.MessageImprint
				i.Nonce = new(big.Int).Add(req.Nonce, big.NewInt(1))
			})
			der, err := asn1.Marshal(tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: token}})
			require.NoError(t, err)
			return der, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := box.SignDocument([]byte("private document"), SignOptions{Timestamp: &TimestampSignOptions{TSARoots: [][]byte{root.Raw}, Fetch: tc.fetch}})
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
	goodOCSP := testpki.OCSP(t, tsa, root, root, rootKey, testpki.OCSPOptions{})
	revoked := testpki.OCSP(t, tsa, root, root, rootKey, testpki.OCSPOptions{Status: 1})
	for _, tc := range []struct {
		name     string
		evidence [][]byte
		fail     bool
	}{{"missing", nil, true}, {"revoked", [][]byte{revoked}, true}, {"good", [][]byte{goodOCSP}, false}} {
		t.Run("TSA OCSP "+tc.name, func(t *testing.T) {
			signed, err := box.SignDocument([]byte("document"), SignOptions{NoTax: true, Timestamp: &TimestampSignOptions{TSARoots: [][]byte{root.Raw}, Fetch: fetch, RevocationOptions: VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: tc.evidence}}})
			if tc.fail {
				require.Error(t, err)
				require.Nil(t, signed)
			} else {
				require.NoError(t, err)
				message, err := cms.ParseSigned(signed)
				require.NoError(t, err)
				tokens, err := message.SignatureTimestampTokens(0)
				require.NoError(t, err)
				require.Len(t, tokens, 1)
			}
		})
	}
	t.Run("cancellation after fetch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		signed, err := box.SignDocumentWithContext(ctx, []byte("input"), SignOptions{Timestamp: &TimestampSignOptions{TSARoots: [][]byte{root.Raw}, Fetch: func(ctx context.Context, input TimestampRequest) ([]byte, error) {
			der, err := fetch(ctx, input)
			cancel()
			return der, err
		}}})
		require.ErrorIs(t, err, context.Canceled)
		require.Nil(t, signed)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := box.SignDocumentWithContext(ctx, nil, SignOptions{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, result)
	result, err = box.SignDocumentWithContext(nil, nil, SignOptions{})
	require.Error(t, err)
	require.Nil(t, result)
	result, err = box.SignDocument(nil, SignOptions{Timestamp: &TimestampSignOptions{Fetch: fetch}})
	require.Error(t, err)
	require.Nil(t, result)
}
