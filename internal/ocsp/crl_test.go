package ocsp_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"crypto-dstu/internal/ocsp"
	"crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func TestDelegatedResponderFullCRL(t *testing.T) {
	issuer, key := testpki.Issue(t, "issuer", nil, nil, testpki.CAExtensions(t))
	other, otherKey := testpki.Issue(t, "other", nil, nil, testpki.CAExtensions(t))
	leaf, _ := testpki.Issue(t, "leaf", issuer, key, nil)
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 9}})
	require.NoError(t, err)
	responder, responderKey := testpki.Issue(t, "responder", issuer, key, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku}})
	response, err := ocsp.ParseResponse(testpki.OCSP(t, leaf, issuer, responder, responderKey, testpki.OCSPOptions{}))
	require.NoError(t, err)
	now := time.Now()
	revoked := pkix.RevokedCertificate{SerialNumber: responder.SerialNumber, RevocationTime: now.Add(-time.Hour)}
	for _, tc := range []struct {
		name                                       string
		opts                                       testpki.CRLOptions
		wrongKey, unrelated, tamper, missing, fail bool
	}{
		{name: "fresh full CRL"},
		{name: "missing", missing: true, fail: true},
		{name: "revoked responder", opts: testpki.CRLOptions{Revoked: []pkix.RevokedCertificate{revoked}}, fail: true},
		{name: "wrong key", wrongKey: true, fail: true},
		{name: "unrelated issuer", unrelated: true, fail: true},
		{name: "tampered signature", tamper: true, fail: true},
		{name: "stale", opts: testpki.CRLOptions{ThisUpdate: now.Add(-8 * 24 * time.Hour)}, fail: true},
		{name: "expired", opts: testpki.CRLOptions{ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(-time.Hour / 2)}, fail: true},
		{name: "future", opts: testpki.CRLOptions{ThisUpdate: now.Add(time.Hour)}, fail: true},
		{name: "delta", opts: testpki.CRLOptions{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Value: []byte{2, 1, 1}}}}, fail: true},
		{name: "scoped", opts: testpki.CRLOptions{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Value: []byte{0x30, 0}}}}, fail: true},
		{name: "unknown critical extension", opts: testpki.CRLOptions{Extensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}}, fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca, signer := issuer, key
			if tc.wrongKey {
				signer = otherKey
			}
			if tc.unrelated {
				ca, signer = other, otherKey
			}
			der := testpki.CRL(t, ca, signer, tc.opts)
			if tc.tamper {
				der[len(der)-1] ^= 1
			}
			policy := ocsp.ValidationPolicy{Time: now, MaxAge: 24 * time.Hour, ClockSkew: time.Minute}
			if !tc.missing {
				policy.ResponderCRLs = [][]byte{der}
			}
			status, err := response.CheckWithPolicy(leaf, issuer, policy)
			if tc.fail {
				require.Error(t, err)
				require.Equal(t, ocsp.Unknown, status)
			} else {
				require.NoError(t, err)
				require.Equal(t, ocsp.Good, status)
			}
		})
	}
	good := testpki.CRL(t, issuer, key, testpki.CRLOptions{})
	bad := testpki.CRL(t, issuer, key, testpki.CRLOptions{Revoked: []pkix.RevokedCertificate{revoked}})
	unrelated := testpki.CRL(t, other, otherKey, testpki.CRLOptions{})
	policy := ocsp.ValidationPolicy{Time: now, MaxAge: time.Hour, ResponderCRLs: [][]byte{unrelated, good}}
	_, err = response.CheckWithPolicy(leaf, issuer, policy)
	require.NoError(t, err)
	for _, crls := range [][][]byte{{good, bad}, {bad, good}} {
		policy.ResponderCRLs = crls
		_, err = response.CheckWithPolicy(leaf, issuer, policy)
		require.Error(t, err)
	}
}
