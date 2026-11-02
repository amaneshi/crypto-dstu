package ua

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func TestRequiredOCSPControlsContentRelease(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", root, rootKey, nil)
	b := NewBox()
	b.caCerts = []*cert.Certificate{root}
	b.keys = []*keyEntry{{privateKey: key, signCert: leaf}}
	content := []byte("protected receipt")
	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	good := testpki.OCSP(t, leaf, root, root, rootKey, testpki.OCSPOptions{})
	for _, tc := range []struct {
		name    string
		options VerificationOptions
		status  RevocationStatus
		fail    bool
	}{
		{"offline explicit status", VerificationOptions{}, RevocationNotChecked, false},
		{"required missing", VerificationOptions{Revocation: RevocationRequireOCSP}, RevocationUnavailable, true},
		{"required good", VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{good}}, RevocationGood, false},
		{"revoked", VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{testpki.OCSP(t, leaf, root, root, rootKey, testpki.OCSPOptions{Status: 1})}}, RevocationRevoked, true},
		{"unknown", VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{testpki.OCSP(t, leaf, root, root, rootKey, testpki.OCSPOptions{Status: 2})}}, RevocationUnknown, true},
		{"stale", VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{testpki.OCSP(t, leaf, root, root, rootKey, testpki.OCSPOptions{ThisUpdate: time.Now().Add(-48 * time.Hour)})}}, RevocationUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := b.UnsignDocumentWithOptions(context.Background(), signed, nil, tc.options)
			require.NotNil(t, result)
			require.Len(t, result.Signers, 1)
			require.Equal(t, tc.status, result.Signers[0].RevocationStatus)
			if tc.fail {
				require.Error(t, err)
				require.Empty(t, result.Content)
				require.False(t, result.Signers[0].Valid)
			} else {
				require.NoError(t, err)
				require.Equal(t, content, result.Content)
				require.True(t, result.Signers[0].Valid)
			}
		})
	}
	t.Run("fetch and cancellation", func(t *testing.T) {
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		options := VerificationOptions{Revocation: RevocationRequireOCSP, FetchOCSP: func(fetchCtx context.Context, request OCSPRequest) ([]byte, error) {
			calls++
			require.Same(t, ctx, fetchCtx)
			require.NotEmpty(t, request.DER)
			require.Equal(t, leaf.Raw, request.SubjectDER)
			require.Equal(t, root.Raw, request.IssuerDER)
			return good, nil
		}}
		result, err := b.UnsignDocumentWithOptions(ctx, signed, nil, options)
		require.NoError(t, err)
		require.Equal(t, content, result.Content)
		require.Equal(t, 1, calls)
		options.FetchOCSP = func(context.Context, OCSPRequest) ([]byte, error) { cancel(); return good, nil }
		result, err = b.UnsignDocumentWithOptions(ctx, signed, nil, options)
		require.ErrorIs(t, err, context.Canceled)
		require.Empty(t, result.Content)
	})
	t.Run("transport failure", func(t *testing.T) {
		failure := errors.New("responder unavailable")
		result, err := b.UnsignDocumentWithOptions(context.Background(), signed, nil, VerificationOptions{Revocation: RevocationRequireOCSP, FetchOCSP: func(context.Context, OCSPRequest) ([]byte, error) { return nil, failure }})
		require.ErrorIs(t, err, failure)
		require.Empty(t, result.Content)
	})
	t.Run("callback cannot change authenticated content", func(t *testing.T) {
		for _, detached := range []bool{false, true} {
			t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
				data, err := b.SignDocument(content, SignOptions{NoTax: true, Detached: detached})
				require.NoError(t, err)
				var original []byte
				if detached {
					original = bytes.Clone(content)
				}
				result, err := b.UnsignDocumentWithOptions(context.Background(), data, original, VerificationOptions{Revocation: RevocationRequireOCSP, FetchOCSP: func(context.Context, OCSPRequest) ([]byte, error) {
					if detached {
						for i := range original {
							original[i] = 'X'
						}
					} else {
						index := bytes.Index(data, content)
						require.GreaterOrEqual(t, index, 0)
						for i := range content {
							data[index+i] = 'X'
						}
					}
					return good, nil
				}})
				require.NoError(t, err)
				require.Equal(t, content, result.Content)
			})
		}
	})
	t.Run("bad signature does not fetch", func(t *testing.T) {
		modified := bytes.Replace(signed, content, bytes.Repeat([]byte{'X'}, len(content)), 1)
		result, err := b.UnsignDocumentWithOptions(context.Background(), modified, nil, VerificationOptions{Revocation: RevocationRequireOCSP, FetchOCSP: func(context.Context, OCSPRequest) ([]byte, error) {
			t.Fatal("fetched before verifying signature")
			return nil, nil
		}})
		require.Error(t, err)
		require.Empty(t, result.Content)
	})
	require.NoError(t, b.VerifyCertWithOptions(context.Background(), leaf.Raw, VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{good}}))
}

func TestRequiredOCSPChecksIntermediateAndExcludesAnchor(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	intermediate, intermediateKey := testpki.Issue(t, "intermediate", root, rootKey, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", intermediate, intermediateKey, nil)
	b := NewBox()
	b.caCerts = []*cert.Certificate{root}
	b.certificates = []*cert.Certificate{intermediate}
	b.keys = []*keyEntry{{privateKey: key, signCert: leaf}}
	signed, err := b.SignDocument([]byte("chain receipt"), SignOptions{NoTax: true})
	require.NoError(t, err)
	leafStatus := testpki.OCSP(t, leaf, intermediate, intermediate, intermediateKey, testpki.OCSPOptions{})
	options := VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{leafStatus}}
	result, err := b.UnsignDocumentWithOptions(context.Background(), signed, nil, options)
	require.Error(t, err)
	require.Empty(t, result.Content)
	options.OCSPResponses = append(options.OCSPResponses, testpki.OCSP(t, intermediate, root, root, rootKey, testpki.OCSPOptions{Status: 1}))
	result, err = b.UnsignDocumentWithOptions(context.Background(), signed, nil, options)
	require.Error(t, err)
	require.Equal(t, RevocationRevoked, result.Signers[0].RevocationStatus)
	require.Empty(t, result.Content)
	options.OCSPResponses[1] = testpki.OCSP(t, intermediate, root, root, rootKey, testpki.OCSPOptions{})
	result, err = b.UnsignDocumentWithOptions(context.Background(), signed, nil, options)
	require.NoError(t, err)
	require.Equal(t, RevocationGood, result.Signers[0].RevocationStatus)
	b.caCerts = []*cert.Certificate{leaf}
	result, err = b.UnsignDocumentWithOptions(context.Background(), signed, nil, VerificationOptions{Revocation: RevocationRequireOCSP})
	require.NoError(t, err)
	require.Equal(t, RevocationNotApplicable, result.Signers[0].RevocationStatus)
}

func TestResponderCRLControlsContentRelease(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", root, rootKey, nil)
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 9}})
	require.NoError(t, err)
	responder, responderKey := testpki.Issue(t, "responder", root, rootKey, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku}})
	b := NewBox()
	b.caCerts = []*cert.Certificate{root}
	b.keys = []*keyEntry{{privateKey: key, signCert: leaf}}
	content := []byte("CRL protected document")
	signed, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	response := testpki.OCSP(t, leaf, root, responder, responderKey, testpki.OCSPOptions{})
	good := testpki.CRL(t, root, rootKey, testpki.CRLOptions{})
	revoked := testpki.CRL(t, root, rootKey, testpki.CRLOptions{Revoked: []pkix.RevokedCertificate{{SerialNumber: responder.SerialNumber, RevocationTime: time.Now().Add(-time.Hour)}}})
	for _, tc := range []struct {
		name string
		crls [][]byte
		fail bool
	}{
		{"no responder proof", nil, true},
		{"authenticated responder", [][]byte{good}, false},
		{"revoked responder", [][]byte{revoked}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := b.UnsignDocumentWithOptions(context.Background(), signed, nil, VerificationOptions{Revocation: RevocationRequireOCSP, OCSPResponses: [][]byte{response}, ResponderCRLs: tc.crls})
			if tc.fail {
				require.Error(t, err)
				require.Empty(t, result.Content)
				require.False(t, result.Signers[0].Valid)
			} else {
				require.NoError(t, err)
				require.Equal(t, content, result.Content)
				require.Equal(t, RevocationGood, result.Signers[0].RevocationStatus)
			}
		})
	}
	_, err = (VerificationOptions{ResponderCRLs: [][]byte{good}}).normalized()
	require.Error(t, err)
	_, err = (VerificationOptions{MaxResponderCRLAge: -time.Second}).normalized()
	require.Error(t, err)
}
