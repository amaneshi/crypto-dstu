//go:build integration

package interop_test

import (
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/ua"
	"github.com/stretchr/testify/require"
)

func TestIITPKCS12Export(t *testing.T) {
	for _, tc := range []struct{ name, curve, password, digest string }{
		{"GOST PB257", "DSTU_PB_257", "disposable-pfx", "gost34311"},
		{"Kupyna PB257 Cyrillic", "DSTU_PB_257", "пароль", "kupyna256"},
		{"Kupyna PB431 Ukrainian", "DSTU_PB_431", "ЇїЄєҐґ", "kupyna512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := dstu4145.GenerateKey(dstu4145.ParamsByName(tc.curve).Curve)
			require.NoError(t, err)
			raw, err := keystore.MarshalRawKey(key)
			require.NoError(t, err)
			digest := oid.GOST34311
			if tc.digest == "kupyna256" {
				digest = oid.Kupyna256
			}
			if tc.digest == "kupyna512" {
				digest = oid.Kupyna512
			}
			certificate := testiit.CertificateForDigest(t, key, false, digest)
			pfx, err := ua.ProtectPKCS12(raw, [][]byte{certificate.Raw}, tc.password)
			require.NoError(t, err)
			parsed, err := keystore.ParsePKCS12(pfx, tc.password)
			require.NoError(t, err)
			require.Len(t, parsed, 1)
			require.Equal(t, key.D, parsed[0].PrivateKey.D)
			require.Equal(t, certificate.Raw, parsed[0].Cert)
			info := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: pfx, Password: tc.password})
			require.True(t, info.OK, info.Error)
			message := []byte("independent PFX export verification\x00\xff")
			for _, detached := range []bool{false, true} {
				certificates := [][]byte{certificate.Raw}
				// This SDK requires the certificate in its discovery store even
				// when a matching certificate bag is present in the PFX.
				signed := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: tc.digest, PrivateKey: pfx,
					Password: tc.password, Data: message, Detached: detached, Certificates: certificates})
				require.True(t, signed.OK, signed.Error)
				_, err = cms.VerifySignedRaw(signed.Data, message, []*cert.Certificate{certificate})
				require.NoError(t, err)
			}
			bad := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: pfx, Password: "wrong-password"})
			require.False(t, bad.OK)
			pfx[len(pfx)-1] ^= 1
			bad = testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: pfx, Password: tc.password})
			require.False(t, bad.OK)
		})
	}
}
