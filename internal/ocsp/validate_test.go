package ocsp_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"crypto-dstu/internal/ocsp"
	"crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatedStatusBindingAndFreshness(t *testing.T) {
	issuer, key := testpki.Issue(t, "issuer", nil, nil, testpki.CAExtensions(t))
	leaf, _ := testpki.Issue(t, "leaf", issuer, key, nil)
	now := time.Now()
	wrongKeyHash := sha1.Sum(issuer.PublicKey.Q.X.Bytes())
	for _, tc := range []struct {
		name    string
		options testpki.OCSPOptions
		want    ocsp.CertStatus
		fail    bool
	}{
		{"good by name", testpki.OCSPOptions{}, ocsp.Good, false},
		{"good by key", testpki.OCSPOptions{ByKey: true}, ocsp.Good, false},
		{"revoked", testpki.OCSPOptions{Status: 1}, ocsp.Revoked, true},
		{"unknown", testpki.OCSPOptions{Status: 2}, ocsp.Unknown, true},
		{"wrong serial", testpki.OCSPOptions{Serial: big.NewInt(1)}, ocsp.Unknown, true},
		{"wrong issuer name", testpki.OCSPOptions{NameHash: bytes.Repeat([]byte{1}, 20)}, ocsp.Unknown, true},
		{"old x-only issuer key hash", testpki.OCSPOptions{KeyHash: wrongKeyHash[:]}, ocsp.Unknown, true},
		{"stale", testpki.OCSPOptions{ThisUpdate: now.Add(-48 * time.Hour)}, ocsp.Unknown, true},
		{"future update", testpki.OCSPOptions{ThisUpdate: now.Add(time.Hour)}, ocsp.Unknown, true},
		{"future production", testpki.OCSPOptions{ProducedAt: now.Add(time.Hour)}, ocsp.Unknown, true},
		{"expired", testpki.OCSPOptions{ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(-10 * time.Minute)}, ocsp.Unknown, true},
		{"missing next update bounded", testpki.OCSPOptions{OmitNextUpdate: true}, ocsp.Good, false},
		{"duplicate matching statuses", testpki.OCSPOptions{Duplicate: true}, ocsp.Unknown, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := testpki.OCSP(t, leaf, issuer, issuer, key, tc.options)
			response, err := ocsp.ParseResponse(der)
			require.NoError(t, err)
			status, err := response.Check(leaf, issuer, time.Now(), 24*time.Hour, 5*time.Minute)
			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, status)
		})
	}
	t.Run("forged signature", func(t *testing.T) {
		der := testpki.OCSP(t, leaf, issuer, issuer, key, testpki.OCSPOptions{})
		der[len(der)-1] ^= 1
		response, err := ocsp.ParseResponse(der)
		require.NoError(t, err)
		_, err = response.Check(leaf, issuer, time.Now(), time.Hour, time.Minute)
		require.Error(t, err)
	})
	t.Run("display fields cannot override signed status", func(t *testing.T) {
		der := testpki.OCSP(t, leaf, issuer, issuer, key, testpki.OCSPOptions{Status: 1})
		response, err := ocsp.ParseResponse(der)
		require.NoError(t, err)
		response.Responses[0].Status = ocsp.Good
		response.ProducedAt = time.Now()
		status, err := response.Check(leaf, issuer, time.Now(), time.Hour, time.Minute)
		require.ErrorIs(t, err, ocsp.ErrRevoked)
		require.Equal(t, ocsp.Revoked, status)
	})
}

func TestMalformedOCSPStatusNeverBecomesGood(t *testing.T) {
	issuer, key := testpki.Issue(t, "issuer", nil, nil, testpki.CAExtensions(t))
	leaf, _ := testpki.Issue(t, "leaf", issuer, key, nil)
	for _, tc := range []struct {
		name   string
		status asn1.RawValue
	}{
		{"wrong class", asn1.RawValue{Class: 0, Tag: 5}},
		{"constructed good", asn1.RawValue{Class: 2, Tag: 0, IsCompound: true}},
		{"nonempty good", asn1.RawValue{Class: 2, Tag: 0, Bytes: []byte{0}}},
		{"unknown choice", asn1.RawValue{Class: 2, Tag: 3}},
		{"bad revoked", asn1.RawValue{Class: 2, Tag: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ocsp.ParseResponse(testpki.OCSP(t, leaf, issuer, issuer, key, testpki.OCSPOptions{StatusValue: &tc.status}))
			require.Error(t, err)
		})
	}
	_, err := ocsp.ParseResponse(testpki.OCSP(t, leaf, issuer, issuer, key, testpki.OCSPOptions{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}}))
	require.Error(t, err)
}

func TestDelegatedResponderRequiresIssuerEKUAndNoCheck(t *testing.T) {
	issuer, key := testpki.Issue(t, "issuer", nil, nil, testpki.CAExtensions(t))
	other, otherKey := testpki.Issue(t, "unrelated issuer", nil, nil, testpki.CAExtensions(t))
	leaf, _ := testpki.Issue(t, "leaf", issuer, key, nil)
	ekuValue, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 9}})
	require.NoError(t, err)
	eku := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: ekuValue}
	noCheck := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}, Value: []byte{5, 0}}
	for _, tc := range []struct {
		name        string
		exts        []pkix.Extension
		wrongIssuer bool
		fail        bool
	}{
		{"authorized", []pkix.Extension{eku, noCheck}, false, false},
		{"missing EKU", []pkix.Extension{noCheck}, false, true},
		{"missing responder revocation exemption", []pkix.Extension{eku}, false, true},
		{"unrelated issuer", []pkix.Extension{eku, noCheck}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, caKey := issuer, key
			if tc.wrongIssuer {
				ca, caKey = other, otherKey
			}
			delegate, delegateKey := testpki.Issue(t, "responder", ca, caKey, tc.exts)
			response, err := ocsp.ParseResponse(testpki.OCSP(t, leaf, issuer, delegate, delegateKey, testpki.OCSPOptions{ByKey: true}))
			require.NoError(t, err)
			_, err = response.Check(leaf, issuer, time.Now(), time.Hour, time.Minute)
			if tc.fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
