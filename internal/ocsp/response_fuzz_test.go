package ocsp

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func fuzzRevocationIdentity(t testing.TB) (*cert.Certificate, *cert.Certificate, *dstu4145.PrivateKey, time.Time) {
	key := &dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(2)}
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	options := testpki.CertificateOptions{
		Key: key, Serial: big.NewInt(1),
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
	}
	issuer, _ := testpki.IssueWithOptions(t, "Public fuzz issuer", nil, nil, options)
	options.Serial = big.NewInt(43)
	subject, _ := testpki.IssueWithOptions(t, "Public fuzz subject", issuer, key, options)
	return issuer, subject, key, now
}

func FuzzParseAndCheckResponse(f *testing.F) {
	issuer, subject, key, now := fuzzRevocationIdentity(f)
	for _, status := range []int{0, 1, 2} {
		for _, byKey := range []bool{false, true} {
			options := testpki.OCSPOptions{
				Status: status, ByKey: byKey, ThisUpdate: now.Add(-time.Minute),
				NextUpdate: now.Add(time.Hour), ProducedAt: now.Add(-time.Minute),
			}
			if status == 1 {
				encoded, err := asn1.Marshal(struct {
					Time time.Time `asn1:"generalized"`
				}{now.Add(-time.Hour)})
				require.NoError(f, err)
				var raw asn1.RawValue
				_, err = asn1.Unmarshal(encoded, &raw)
				require.NoError(f, err)
				options.StatusValue = &asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: raw.Bytes}
			}
			seed := testpki.OCSP(f, subject, issuer, issuer, key, options)
			parsed, err := ParseResponse(seed)
			require.NoError(f, err)
			if status == 0 {
				got, err := parsed.Check(subject, issuer, now, time.Hour, 0)
				require.NoError(f, err)
				require.Equal(f, Good, got)
			} else if status == 1 {
				got, err := parsed.Check(subject, issuer, now, time.Hour, 0)
				require.True(f, errors.Is(err, ErrRevoked))
				require.Equal(f, Revoked, got)
			}
			f.Add(seed)
		}
	}
	f.Add([]byte{0x30, 0})
	f.Add([]byte{0x30, 3, 0x0a, 1, 1}) // unsuccessful responder status
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		original := bytes.Clone(data)
		response, err := ParseResponse(data)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, response)
			return
		}
		junk, err := ParseResponse(append(bytes.Clone(data), 0))
		require.Error(t, err)
		require.Nil(t, junk)
		status, err := response.Check(subject, issuer, now, time.Hour, 0)
		if err == nil {
			require.Equal(t, Good, status)
		} else {
			require.NotEqual(t, Good, status, "failed authentication returned a good status")
		}
		require.Equal(t, original, data)
	})
}

func FuzzCheckResponderCRL(f *testing.F) {
	issuer, responder, key, now := fuzzRevocationIdentity(f)
	for _, revoked := range []bool{false, true} {
		options := testpki.CRLOptions{ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour)}
		if revoked {
			options.Revoked = []pkix.RevokedCertificate{{
				SerialNumber: responder.SerialNumber, RevocationTime: now.Add(-time.Hour),
			}}
		}
		seed := testpki.CRL(f, issuer, key, options)
		if !revoked {
			require.NoError(f, checkResponderCRL(seed, responder, issuer, now, 24*time.Hour, 0))
		}
		f.Add(seed)
	}
	f.Add([]byte{0x30, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		original := bytes.Clone(data)
		if checkResponderCRL(data, responder, issuer, now, 24*time.Hour, 0) == nil {
			require.Error(t, checkResponderCRL(append(bytes.Clone(data), 0), responder, issuer, now, 24*time.Hour, 0))
			bad := bytes.Clone(data)
			bad[len(bad)-1] ^= 1
			require.Error(t, checkResponderCRL(bad, responder, issuer, now, 24*time.Hour, 0))
		}
		require.Equal(t, original, data)
	})
}
