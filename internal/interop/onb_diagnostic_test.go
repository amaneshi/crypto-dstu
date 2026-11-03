//go:build integration

package interop_test

import (
	"bytes"
	"math/big"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

// An opt-in comparison of native named and synthetic explicit ONB profiles.
func TestIITONBDiagnostic(t *testing.T) {
	if os.Getenv("IIT_ONB_DIAGNOSTIC") != "1" {
		t.Skip("enable explicit ONB diagnostic")
	}
	invalid := testiit.Invoke(t, testiit.Request{Operation: "cert-parse", Data: []byte{0x30, 0}})
	require.False(t, invalid.OK)
	require.Contains(t, invalid.Error, "EUParseCertificateEx:")
	for _, name := range []string{"DSTU_PB_257", "DSTU_ONB_173", "DSTU_ONB_179", "DSTU_ONB_191", "DSTU_ONB_233", "DSTU_ONB_431"} {
		t.Run(name, func(t *testing.T) {
			curve := dstu4145.ParamsByName(name).Curve
			nBits := new(big.Int).SetBytes(curve.N).BitLen()
			scalar := new(big.Int).Lsh(big.NewInt(1), uint(nBits-2))
			scalar.Add(scalar, big.NewInt(0x12345)) // intentionally public full-width fixture
			key := &dstu4145.PrivateKey{Curve: curve, D: scalar}
			raw, err := keystore.MarshalRawKey(key)
			require.NoError(t, err)
			container, err := keystore.MarshalKey6(raw, "disposable-onb", bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
			require.NoError(t, err)
			info := testiit.Invoke(t, testiit.Request{Operation: "key-info", PrivateKey: container, Password: "disposable-onb"})
			require.True(t, info.OK, info.Error)
			t.Logf("key-info: ok=%t error=%s", info.OK, info.Error)
			for _, named := range []bool{false, true} {
				var certificate *cert.Certificate
				if named {
					certificate = testiit.NamedCertificate(t, key)
				} else {
					certificate = testiit.Certificate(t, key, false)
				}
				message := []byte("independent ONB diagnostic\x00\xff")
				parsed := testiit.Invoke(t, testiit.Request{Operation: "cert-parse", Data: certificate.Raw})
				require.True(t, parsed.OK, parsed.Error)
				t.Logf("named=%t certificate parse: ok=%t error=%s", named, parsed.OK, parsed.Error)
				signed, err := cms.Sign(message, key, certificate, cms.SignOptions{})
				require.NoError(t, err)
				verified := testiit.Invoke(t, testiit.Request{Operation: "verify", Signature: signed, Data: message, Certificates: [][]byte{certificate.Raw}})
				t.Logf("named=%t verify: ok=%t error=%s", named, verified.OK, verified.Error)
				native := testiit.Invoke(t, testiit.Request{Operation: "sign", PrivateKey: container, Password: "disposable-onb", Data: message, Certificates: [][]byte{certificate.Raw}})
				t.Logf("named=%t sign: ok=%t error=%s", named, native.OK, native.Error)
				if !curve.IsONB() || named {
					require.True(t, verified.OK, verified.Error)
					require.True(t, native.OK, native.Error)
				} else {
					// Known ONB rejections are diagnostic results, not positive
					// interoperability. Every other adapter failure still fails.
					if !verified.OK {
						require.Contains(t, verified.Error, "EUVerifyDataInternalOnTimeEx: IIT error 50:")
					}
					if !native.OK {
						require.Regexp(t, `EUReadPrivateKeyBinary: IIT error 5[01]:`, native.Error)
					}
				}
				if verified.OK {
					require.Equal(t, message, verified.Data)
				}
				if native.OK {
					_, err = cms.VerifySignedRaw(native.Data, message, []*cert.Certificate{certificate})
					require.NoError(t, err)
				}
			}
		})
	}
}
