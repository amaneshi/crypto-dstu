//go:build integration

package interop_test

import (
	"bytes"
	"encoding/asn1"
	"os"
	"testing"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/oid"
	"crypto-dstu/internal/testiit"
	"crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITGoSigningProfiles(t *testing.T) {
	if os.Getenv("IIT_ORACLE") == "" {
		t.Skip("set native IIT adapter configuration")
	}
	for _, tc := range []struct {
		name, curve string
		digest      asn1.ObjectIdentifier
	}{
		{"GOST/PB191", "DSTU_PB_191", oid.GOST34311},
		{"GOST/PB257", "DSTU_PB_257", oid.GOST34311},
		{"GOST/PB307", "DSTU_PB_307", oid.GOST34311},
		{"GOST/PB367", "DSTU_PB_367", oid.GOST34311},
		{"GOST/PB431", "DSTU_PB_431", oid.GOST34311},
		{"Kupyna256/PB257", "DSTU_PB_257", oid.Kupyna256},
		{"Kupyna512/PB431", "DSTU_PB_431", oid.Kupyna512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := dstu4145.GenerateKey(dstu4145.ParamsByName(tc.curve).Curve)
			require.NoError(t, err)
			c := testiit.CertificateForDigest(t, key, false, tc.digest)
			content := []byte("independent profile test\x00\xff\r\nТест")
			for _, detached := range []bool{false, true} {
				t.Run(map[bool]string{false: "attached", true: "detached"}[detached], func(t *testing.T) {
					signed, err := cms.Sign(content, key, c, cms.SignOptions{DigestAlgorithm: tc.digest, Detached: detached})
					require.NoError(t, err)
					require.Equal(t, tc.digest, testiit.SignerDigest(t, signed))
					_, err = cms.VerifySignedRaw(signed, content, []*cert.Certificate{c})
					require.NoError(t, err)
					result := testiit.Invoke(t, testiit.Request{Operation: "verify", Data: content, Signature: signed, Detached: detached, Certificates: [][]byte{c.Raw}})
					require.True(t, result.OK, result.Error)
					require.Equal(t, content, result.Data)
					changed := bytes.Repeat([]byte{'X'}, len(content))
					altered := signed
					if !detached {
						altered = bytes.Replace(signed, content, changed, 1)
					}
					rejected := testiit.Invoke(t, testiit.Request{Operation: "verify", Data: changed, Signature: altered, Detached: detached, Certificates: [][]byte{c.Raw}})
					require.False(t, rejected.OK, "modified content must fail native verification")
				})
			}
		})
	}
}

func TestIITNativeSigningProfiles(t *testing.T) {
	if os.Getenv("IIT_ORACLE") == "" {
		t.Skip("set native IIT adapter configuration")
	}
	const basePassword = "disposable-profile-key"
	for _, tc := range []struct {
		name, curve, digestName string
		digest                  asn1.ObjectIdentifier
		nativeBits              int
	}{
		{"GOST/PB191", "DSTU_PB_191", "gost34311", oid.GOST34311, 191},
		{"GOST/PB257", "DSTU_PB_257", "gost34311", oid.GOST34311, 257},
		{"GOST/PB307", "DSTU_PB_307", "gost34311", oid.GOST34311, 307},
		{"GOST/PB307 GoKey6", "DSTU_PB_307", "gost34311", oid.GOST34311, 0},
		{"GOST/PB367", "DSTU_PB_367", "gost34311", oid.GOST34311, 0},
		{"GOST/PB431", "DSTU_PB_431", "gost34311", oid.GOST34311, 0},
		{"Kupyna256/PB257", "DSTU_PB_257", "kupyna256", oid.Kupyna256, 257},
		{"Kupyna512/PB431", "DSTU_PB_431", "kupyna512", oid.Kupyna512, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password := basePassword
			if tc.digest.Equal(oid.Kupyna256) {
				password = string(bytes.Repeat([]byte{'K'}, 32))
			}
			var key *dstu4145.PrivateKey
			var container []byte
			if tc.nativeBits > 0 {
				family := "gost34311"
				if tc.digest.Equal(oid.Kupyna256) {
					family = "kupyna"
				}
				generated := testiit.Invoke(t, testiit.Request{Operation: "generate", KeyFamily: family, KeyBits: tc.nativeBits, Password: password})
				require.True(t, generated.OK, generated.Error)
				pairs, err := keystore.ParsePKCS12(generated.Data, password)
				require.NoError(t, err)
				require.Len(t, pairs, 1)
				key = pairs[0].PrivateKey
				container = generated.Data
				_, wrongPasswordErr := keystore.ParsePKCS12(container, "incorrect password")
				require.Error(t, wrongPasswordErr)
			} else {
				var err error
				key, err = dstu4145.GenerateKey(dstu4145.ParamsByName(tc.curve).Curve)
				require.NoError(t, err)
				raw, err := keystore.MarshalRawKey(key)
				require.NoError(t, err)
				container, err = keystore.MarshalKey6(raw, password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
				require.NoError(t, err)
			}
			require.Equal(t, dstu4145.ParamsByName(tc.curve).Curve.M, key.Curve.M)
			c := testiit.CertificateForDigest(t, key, false, tc.digest)
			content := []byte("native profile signature\x00\xff\r\nТест")
			for _, detached := range []bool{false, true} {
				t.Run(map[bool]string{false: "attached", true: "detached"}[detached], func(t *testing.T) {
					result := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: tc.digestName, Data: content, Detached: detached, Certificates: [][]byte{c.Raw}, PrivateKey: container, Password: password})
					require.True(t, result.OK, result.Error)
					require.Equal(t, tc.digest, testiit.SignerDigest(t, result.Data), "SDK output must use the requested profile")
					require.Equal(t, []asn1.ObjectIdentifier{tc.digest}, testiit.DigestSet(t, result.Data))
					message, err := cms.VerifySignedRaw(result.Data, content, []*cert.Certificate{c})
					require.NoError(t, err)
					require.True(t, message.Signers[0].Valid)
					changed := bytes.Repeat([]byte{'X'}, len(content))
					altered := result.Data
					if !detached {
						altered = bytes.Replace(altered, content, changed, 1)
					}
					_, err = cms.VerifySignedRaw(altered, changed, []*cert.Certificate{c})
					require.Error(t, err, "changed native signed content must fail")
				})
			}
		})
	}
}
