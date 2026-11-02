//go:build integration

package interop_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITKeyImportScalarBoundaries(t *testing.T) {
	const password = "disposable-import-test"
	for _, curveName := range []string{"DSTU_PB_307", "DSTU_PB_431"} {
		t.Run(curveName, func(t *testing.T) {
			curve := dstu4145.ParamsByName(curveName).Curve
			n := new(big.Int).SetBytes(curve.N)
			limit := new(big.Int).Lsh(big.NewInt(1), uint(n.BitLen()-1))
			for _, tc := range []struct {
				name     string
				scalar   *big.Int
				accepted bool
			}{
				{"minimum", big.NewInt(1), true},
				{"maximum DSTU scalar", new(big.Int).Sub(limit, big.NewInt(1)), true},
				{"first excluded scalar", limit, false},
				{"order minus one", new(big.Int).Sub(n, big.NewInt(1)), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					key := &dstu4145.PrivateKey{D: tc.scalar, Curve: curve}
					raw, err := keystore.MarshalRawKey(key)
					require.NoError(t, err)
					container, err := keystore.MarshalKey6(raw, password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
					require.NoError(t, err)
					info := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: container, Password: password})
					require.Equal(t, tc.accepted, info.OK, info.Error)
					if tc.accepted {
						require.NotEmpty(t, info.Data)
					} else {
						require.Equal(t, uint32(33), info.Code)
					}
				})
			}
		})
	}
}

func TestIITRepackedNativeKey(t *testing.T) {
	const password = "disposable-repack-test"
	generated := testiit.Invoke(t, testiit.Request{Operation: "generate", KeyBits: 307, Password: password})
	require.True(t, generated.OK, generated.Error)
	pairs, err := keystore.ParsePKCS12(generated.Data, password)
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	key := pairs[0].PrivateKey
	certificate := testiit.Certificate(t, key, false)
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	repacked, err := keystore.MarshalKey6(raw, password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
	require.NoError(t, err)
	var publicInfo []byte
	for _, tc := range []struct {
		name string
		data []byte
	}{{"original", generated.Data}, {"repacked", repacked}} {
		t.Run(tc.name, func(t *testing.T) {
			info := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: tc.data, Password: password})
			require.True(t, info.OK, info.Error)
			if publicInfo == nil {
				publicInfo = info.Data
			} else {
				require.Equal(t, publicInfo, info.Data, "repacking must preserve native public key information")
			}
			content := []byte("public repacked key test")
			signed := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: "gost34311", Data: content, PrivateKey: tc.data, Password: password, Certificates: [][]byte{certificate.Raw}})
			require.True(t, signed.OK, signed.Error)
			require.Equal(t, oid.GOST34311, testiit.SignerDigest(t, signed.Data))
			_, err = cms.VerifySignedRaw(signed.Data, content, []*cert.Certificate{certificate})
			require.NoError(t, err)
		})
	}
}
