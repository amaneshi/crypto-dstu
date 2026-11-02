//go:build integration

package keystore

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/stretchr/testify/require"
)

func TestIITPKCS12Integrity(t *testing.T) {
	for _, family := range []string{"gost34311", "kupyna"} {
		t.Run(family, func(t *testing.T) {
			password := "disposable-integrity-test"
			if family == "kupyna" {
				password = strings.Repeat("K", 32)
			}
			generated := testiit.Invoke(t, testiit.Request{Operation: "generate", KeyBits: 257, KeyFamily: family, Password: password})
			require.True(t, generated.OK, generated.Error)
			var pfx pfxASN
			_, err := asn1.Unmarshal(generated.Data, &pfx)
			require.NoError(t, err)
			var mac pkcs12MacData
			_, err = asn1.Unmarshal(pfx.MacData.FullBytes, &mac)
			require.NoError(t, err)
			t.Logf("IIT PFX MAC algorithm=%s; iterations=%d; digest length=%d", mac.MAC.Algorithm.Algorithm, mac.Iterations, len(mac.MAC.Digest))
			pairs, err := ParsePKCS12(generated.Data, password)
			require.NoError(t, err)
			require.Len(t, pairs, 1)
			pairs, err = ParsePKCS12(generated.Data, "wrong password")
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
			pfx.AuthSafe.Content.Bytes[len(pfx.AuthSafe.Content.Bytes)-1] ^= 1
			altered, err := asn1.Marshal(pfx)
			require.NoError(t, err)
			pairs, err = ParsePKCS12(altered, password)
			require.ErrorIs(t, err, ErrPKCS12Integrity)
			require.Nil(t, pairs)
		})
	}
}

func TestIITPKCS12NonASCII(t *testing.T) {
	for _, family := range []string{"gost34311", "kupyna"} {
		t.Run(family, func(t *testing.T) {
			for _, tc := range []struct{ name, password string }{{"Cyrillic", "пароль"}, {"Ukrainian", "ЇїЄєҐґ"}} {
				t.Run(tc.name, func(t *testing.T) {
					generated := testiit.Invoke(t, testiit.Request{
						Operation: "generate", KeyBits: 257, KeyFamily: family, Password: tc.password,
					})
					require.True(t, generated.OK, generated.Error)
					pairs, err := ParsePKCS12(generated.Data, tc.password)
					require.NoError(t, err)
					require.Len(t, pairs, 1)
					raw, err := MarshalRawKey(pairs[0].PrivateKey)
					require.NoError(t, err)
					reprotected, err := MarshalKey6Kalyna(
						raw, tc.password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 32),
					)
					require.NoError(t, err)
					// EUGetKeyInfoBinary includes profile-dependent key identifiers;
					// raw PKCS#8 re-encoding may change that metadata. Prove the
					// actual public/private key correspondence with signatures.
					digest, digestName := oid.GOST34311, "gost34311"
					if family == "kupyna" {
						digest, digestName = oid.Kupyna256, "kupyna256"
					}
					certificate := testiit.CertificateForDigest(t, pairs[0].PrivateKey, false, digest)
					message := []byte("public non-ASCII password interoperability test")
					for _, container := range [][]byte{generated.Data, reprotected} {
						signed := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: digestName, PrivateKey: container,
							Password: tc.password, Certificates: [][]byte{certificate.Raw}, Data: message})
						require.True(t, signed.OK, signed.Error)
						_, err = cms.VerifySignedRaw(signed.Data, message, []*cert.Certificate{certificate})
						require.NoError(t, err)
					}
					bad, err := ParsePKCS12(generated.Data, tc.password+"wrong")
					require.ErrorIs(t, err, ErrPKCS12Integrity)
					require.Nil(t, bad)
				})
			}
		})
	}
}
