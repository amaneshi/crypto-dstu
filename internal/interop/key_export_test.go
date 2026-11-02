//go:build integration

package interop_test

import (
	"bytes"
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

func TestIITKalynaKeyExport(t *testing.T) {
	for _, tc := range []struct{ name, curve, password, digest string }{
		{"PB257 short password", "DSTU_PB_257", "test-export", "kupyna256"},
		{"PB257 full password", "DSTU_PB_257", string(bytes.Repeat([]byte{'K'}, 32)), "kupyna256"},
		{"PB431", "DSTU_PB_431", "test-export-pb431", "kupyna512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := dstu4145.GenerateKey(dstu4145.ParamsByName(tc.curve).Curve)
			require.NoError(t, err)
			raw, err := keystore.MarshalRawKey(key)
			require.NoError(t, err)
			container, err := ua.ProtectKey(raw, tc.password)
			require.NoError(t, err)
			read, err := keystore.ParseKey6(container, tc.password)
			require.NoError(t, err)
			require.Equal(t, key.D, read.D)
			info := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: container, Password: tc.password})
			require.True(t, info.OK, info.Error)
			legacy, err := keystore.MarshalKey6(raw, tc.password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
			require.NoError(t, err)
			baseline := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: legacy, Password: tc.password})
			require.True(t, baseline.OK, baseline.Error)
			require.Equal(t, baseline.Data, info.Data)
			digest := oid.Kupyna256
			if tc.digest == "kupyna512" {
				digest = oid.Kupyna512
			}
			certificate := testiit.CertificateForDigest(t, key, false, digest)
			content := []byte("public Kalyna key export check\x00\xff")
			for _, detached := range []bool{false, true} {
				signed := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: tc.digest, Detached: detached, Data: content, PrivateKey: container, Password: tc.password, Certificates: [][]byte{certificate.Raw}})
				require.True(t, signed.OK, signed.Error)
				require.Equal(t, digest, testiit.SignerDigest(t, signed.Data))
				_, err := cms.VerifySignedRaw(signed.Data, content, []*cert.Certificate{certificate})
				require.NoError(t, err)
			}
			bad := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: container, Password: "wrong-password"})
			require.False(t, bad.OK)
		})
	}
}
