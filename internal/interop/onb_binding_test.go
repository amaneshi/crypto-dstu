//go:build integration

package interop_test

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/stretchr/testify/require"
)

// This positive matrix accepts no native failures. All keys are public fixtures.
func TestIITONBNamedCertificates(t *testing.T) {
	for _, params := range dstu4145.AllParams() {
		if !params.Curve.IsONB() {
			continue
		}
		t.Run(params.Name, func(t *testing.T) {
			nBits := new(big.Int).SetBytes(params.Curve.N).BitLen()
			full := new(big.Int).Lsh(big.NewInt(1), uint(nBits-2))
			full.Add(full, big.NewInt(0x12345))
			for i := range 4 {
				d := new(big.Int).Add(full, big.NewInt(int64(i)*0x13579))
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					key := &dstu4145.PrivateKey{Curve: params.Curve, D: d}
					raw, err := keystore.MarshalRawKey(key)
					require.NoError(t, err)
					container, err := keystore.MarshalKey6(raw, "disposable-onb", bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 8))
					require.NoError(t, err)
					info := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: container, Password: "disposable-onb"})
					require.True(t, info.OK, info.Error)
					compressed := key.Public().Q.Compress()
					slices.Reverse(compressed)
					encoded, err := asn1.Marshal(compressed)
					require.NoError(t, err)
					h := gost34311.New()
					h.Write(encoded)
					// The native result is opaque; do not assume a fixed ABI offset.
					require.True(t, bytes.Contains(info.Data, h.Sum(nil)), "native public-key identifier differs")
					certificate := testiit.NamedCertificate(t, key)
					parsed := testiit.Invoke(t, testiit.Request{Operation: "cert-parse", Data: certificate.Raw})
					require.True(t, parsed.OK, parsed.Error)
					message := []byte("independent ONB CMS regression\x00\xff")
					for _, detached := range []bool{false, true} {
						t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
							signed, err := cms.Sign(message, key, certificate, cms.SignOptions{Detached: detached})
							require.NoError(t, err)
							verified := testiit.Invoke(t, testiit.Request{Operation: "verify", Signature: signed, Data: message, Detached: detached, Certificates: [][]byte{certificate.Raw}})
							require.True(t, verified.OK, verified.Error)
							require.Equal(t, message, verified.Data)
							changed := bytes.Repeat([]byte{'X'}, len(message))
							altered := signed
							if !detached {
								altered = bytes.Replace(signed, message, changed, 1)
							}
							rejected := testiit.Invoke(t, testiit.Request{Operation: "verify", Signature: altered, Data: changed, Detached: detached, Certificates: [][]byte{certificate.Raw}})
							require.False(t, rejected.OK, "modified content must fail native verification")
							native := testiit.Invoke(t, testiit.Request{Operation: "sign", PrivateKey: container, Password: "disposable-onb", Data: message, Detached: detached, Certificates: [][]byte{certificate.Raw}})
							require.True(t, native.OK, native.Error)
							_, err = cms.VerifySignedRaw(native.Data, message, []*cert.Certificate{certificate})
							require.NoError(t, err)
							if detached {
								_, err = cms.VerifySignedRaw(native.Data, []byte("changed"), []*cert.Certificate{certificate})
								require.Error(t, err)
							}
						})
					}
				})
			}
		})
	}
}
