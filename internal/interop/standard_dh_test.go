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
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITStandardDHKalyna(t *testing.T) {
	for _, name := range []string{"DSTU_PB_257", "DSTU_ONB_173", "DSTU_ONB_179", "DSTU_ONB_191", "DSTU_ONB_233", "DSTU_ONB_431"} {
		t.Run(name, func(t *testing.T) {
			curve := dstu4145.ParamsByName(name).Curve
			d := new(big.Int).Lsh(big.NewInt(1), uint(new(big.Int).SetBytes(curve.N).BitLen()-2))
			d.Add(d, big.NewInt(0x12345))
			recipientKey := &dstu4145.PrivateKey{Curve: curve, D: d}
			senderKey := &dstu4145.PrivateKey{Curve: curve, D: new(big.Int).Add(d, big.NewInt(0x13579))}
			sender, recipient := testiit.NamedCertificate(t, senderKey), testiit.NamedCertificate(t, recipientKey)
			protect := func(key *dstu4145.PrivateKey) []byte {
				raw, err := keystore.MarshalRawKey(key)
				require.NoError(t, err)
				container, err := keystore.MarshalKey6(raw, "disposable-standard-dh", bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 8))
				require.NoError(t, err)
				return container
			}
			senderContainer, recipientContainer := protect(senderKey), protect(recipientKey)
			certificates := [][]byte{sender.Raw, recipient.Raw}
			type sample struct {
				Cipher   string
				Envelope []byte
			}
			var samples []sample
			var sdkHash string
			for _, profile := range []struct {
				name      string
				algorithm asn1.ObjectIdentifier
			}{{"kalyna256-cfb", cms.OIDKalyna256CFB}, {"kalyna256-ofb", cms.OIDKalyna256OFB}} {
				for _, size := range []int{1, 33, 65} {
					t.Run(fmt.Sprintf("%s/%d", profile.name, size), func(t *testing.T) {
						content := make([]byte, size)
						for i := range content {
							content[i] = byte(i)
						}
						for _, mode := range []string{"dynamic", "static", "embedded"} {
							t.Run(mode, func(t *testing.T) {
								options := cms.EncryptOptions{Algorithm: profile.algorithm, AgreementAlgorithm: cms.OIDKupynaStandardDH}
								if mode != "dynamic" {
									options.OriginatorCertificate = sender
									options.EmbedOriginatorCertificate = mode == "embedded"
								}
								encoded, err := cms.EncryptWithOptions(content, []*cert.Certificate{recipient}, senderKey, options)
								require.NoError(t, err)
								parsed, err := cms.ParseEnveloped(encoded)
								require.NoError(t, err)
								require.Equal(t, cms.OIDKupynaStandardDH, parsed.Recipients[0].AgreementAlgorithm)
								var discovery []*cert.Certificate
								if mode == "static" {
									discovery = []*cert.Certificate{sender}
								}
								plain, err := cms.DecryptEnveloped(parsed, recipientKey, recipient, discovery...)
								require.NoError(t, err)
								require.Equal(t, content, plain)
								nativeCertificates := certificates
								if mode == "embedded" {
									nativeCertificates = [][]byte{recipient.Raw}
								}
								native := testiit.Invoke(t, testiit.Request{Operation: "decrypt", PrivateKey: recipientContainer, Password: "disposable-standard-dh", Certificates: nativeCertificates, Data: encoded})
								require.True(t, native.OK, native.Error)
								require.Equal(t, content, native.Data)
								if size == 65 {
									plain, err = cms.DecryptEnveloped(parsed, senderKey, recipient, discovery...)
									require.Error(t, err)
									require.Nil(t, plain)
									parsed.Recipients[0].WrappedCEK[32] ^= 1
									plain, err = cms.DecryptEnveloped(parsed, recipientKey, recipient, discovery...)
									require.Error(t, err)
									require.Nil(t, plain)
								}
							})
						}
						native := testiit.Invoke(t, testiit.Request{Operation: "encrypt", Cipher: profile.name, StaticOriginator: true, PrivateKey: senderContainer, Password: "disposable-standard-dh", Certificates: certificates, Recipients: [][]byte{recipient.Raw}, Data: content})
						require.True(t, native.OK, native.Error)
						original, err := cms.ParseEnveloped(native.Data)
						require.NoError(t, err)
						if curve.IsONB() {
							plain, err := cms.DecryptEnveloped(original, recipientKey, recipient, sender)
							require.ErrorContains(t, err, "unsupported ONB Kupyna agreement")
							require.Nil(t, plain)
							// The native ONB producer uses h=1 but tags cofactor DH. Only
							// this reference adapter relabels the known public fixture.
							cofactorDER, err := asn1.Marshal(cms.OIDKupynaDH)
							require.NoError(t, err)
							standardDER, err := asn1.Marshal(cms.OIDKupynaStandardDH)
							require.NoError(t, err)
							require.Greater(t, bytes.Count(native.Data, cofactorDER), 0)
							corrected := bytes.ReplaceAll(native.Data, cofactorDER, standardDER)
							parsed, err := cms.ParseEnveloped(corrected)
							require.NoError(t, err)
							plain, err = cms.DecryptEnveloped(parsed, recipientKey, recipient, sender)
							require.NoError(t, err)
							require.Equal(t, content, plain)
							decrypted := testiit.Invoke(t, testiit.Request{Operation: "decrypt", PrivateKey: recipientContainer, Password: "disposable-standard-dh", Certificates: certificates, Data: corrected})
							require.True(t, decrypted.OK, decrypted.Error)
							require.Equal(t, content, decrypted.Data)
							if size == 65 {
								samples = append(samples, sample{profile.name, native.Data})
								sdkHash = native.SDKHash
							}
						} else {
							plain, err := cms.DecryptEnveloped(original, recipientKey, recipient, sender)
							require.NoError(t, err)
							require.Equal(t, content, plain)
						}
					})
				}
			}
			if directory := os.Getenv("IIT_CAPTURE_STANDARD_DH_DIR"); directory != "" && curve.IsONB() {
				require.True(t, filepath.IsAbs(directory))
				require.NoError(t, os.MkdirAll(directory, 0700))
				fixture := struct {
					Producer, SDKHash, Curve, WireNote      string
					SenderCertificate, RecipientCertificate []byte
					Samples                                 []sample
				}{
					"IIT x86 EUSignCP 1.3.1.224", sdkHash, name,
					"Unmodified native ONB envelopes use h=1 but carry cofactor-DH OID 7. Only test adapters relabel to standard-DH OID 8. Public recipient d=2^(bitlen(n)-2)+0x12345; sender adds 0x13579; plaintext bytes 00..40.",
					sender.Raw, recipient.Raw, samples}
				data, err := json.MarshalIndent(fixture, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(directory, name+".json"), append(data, '\n'), 0600))
			}
		})
	}
}
