//go:build integration

package interop_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

// Native production currently labels ONB Kupyna signatures with PB OIDs. The
// consumer must reject that mismatch. Explicit test-only relabeling checks the
// independently produced signature under the registered ONB wire identifier.
func TestIITONBKupynaCMS(t *testing.T) {
	for _, name := range []string{"DSTU_ONB_173", "DSTU_ONB_179", "DSTU_ONB_191", "DSTU_ONB_233", "DSTU_ONB_431"} {
		t.Run(name, func(t *testing.T) {
			curve := dstu4145.ParamsByName(name).Curve
			nBits := new(big.Int).SetBytes(curve.N).BitLen()
			d := new(big.Int).Lsh(big.NewInt(1), uint(nBits-2))
			d.Add(d, big.NewInt(0x12345))
			key := &dstu4145.PrivateKey{Curve: curve, D: d}
			certificate := testiit.NamedCertificate(t, key)
			raw, err := keystore.MarshalRawKey(key)
			require.NoError(t, err)
			container, err := keystore.MarshalKey6(raw, "disposable-onb", bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 8))
			require.NoError(t, err)
			content := []byte("independent ONB Kupyna CMS\x00\xff\r\nТест")
			type sample struct {
				Bits      int
				Detached  bool
				Signature []byte
			}
			var samples []sample
			var sdkHash string
			for _, profile := range []struct {
				bits            int
				digest, pb, onb asn1.ObjectIdentifier
			}{
				{256, oid.Kupyna256, oid.DSTU4145WithKupyna256, oid.DSTU4145ONBWithKupyna256},
				{512, oid.Kupyna512, oid.DSTU4145WithKupyna512, oid.DSTU4145ONBWithKupyna512},
			} {
				for _, detached := range []bool{false, true} {
					t.Run(fmt.Sprintf("%d/detached=%t", profile.bits, detached), func(t *testing.T) {
						signed, err := cms.Sign(content, key, certificate, cms.SignOptions{DigestAlgorithm: profile.digest, Detached: detached})
						require.NoError(t, err)
						require.Equal(t, profile.onb, testiit.SignerSignatureAlgorithm(t, signed))
						verified := testiit.Invoke(t, testiit.Request{Operation: "verify", Signature: signed, Data: content, Detached: detached, Certificates: [][]byte{certificate.Raw}})
						require.True(t, verified.OK, verified.Error)
						require.Equal(t, content, verified.Data)
						native := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: fmt.Sprintf("kupyna%d", profile.bits), Data: content, Detached: detached, PrivateKey: container, Password: "disposable-onb", Certificates: [][]byte{certificate.Raw}})
						require.True(t, native.OK, native.Error)
						require.Equal(t, profile.digest, testiit.SignerDigest(t, native.Data))
						require.Equal(t, profile.pb, testiit.SignerSignatureAlgorithm(t, native.Data))
						_, err = cms.VerifySignedRaw(native.Data, content, []*cert.Certificate{certificate})
						require.ErrorContains(t, err, "signature algorithm")
						pbDER, err := asn1.Marshal(profile.pb)
						require.NoError(t, err)
						onbDER, err := asn1.Marshal(profile.onb)
						require.NoError(t, err)
						require.Equal(t, 1, bytes.Count(native.Data, pbDER))
						corrected := bytes.Replace(native.Data, pbDER, onbDER, 1)
						_, err = cms.VerifySignedRaw(corrected, content, []*cert.Certificate{certificate})
						require.NoError(t, err)
						verified = testiit.Invoke(t, testiit.Request{Operation: "verify", Signature: corrected, Data: content, Detached: detached, Certificates: [][]byte{certificate.Raw}})
						require.True(t, verified.OK, verified.Error)
						changed := bytes.Repeat([]byte{'X'}, len(content))
						if !detached {
							corrected = bytes.Replace(corrected, content, changed, 1)
						}
						_, err = cms.VerifySignedRaw(corrected, changed, []*cert.Certificate{certificate})
						require.Error(t, err)
						verified = testiit.Invoke(t, testiit.Request{Operation: "verify", Signature: corrected, Data: changed, Detached: detached, Certificates: [][]byte{certificate.Raw}})
						require.False(t, verified.OK, "modified content must fail")
						sdkHash = native.SDKHash
						samples = append(samples, sample{profile.bits, detached, native.Data})
					})
				}
			}
			if directory := os.Getenv("IIT_CAPTURE_ONB_KUPYNA_DIR"); directory != "" {
				require.True(t, filepath.IsAbs(directory))
				require.NoError(t, os.MkdirAll(directory, 0700))
				fixture := struct {
					Producer, SDKHash, Curve, WireNote string
					Certificate, Content               []byte
					Samples                            []sample
				}{"IIT x86 EUSignCP 1.3.1.224", sdkHash, name,
					"Unmodified native signatures carry PB signature OIDs; only test adapters explicitly relabel them as ONB. Public scalar 2^(bitlen(n)-2)+0x12345.",
					certificate.Raw, content, samples}
				data, err := json.MarshalIndent(fixture, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(directory, name+".json"), append(data, '\n'), 0600))
			}
		})
	}
}
