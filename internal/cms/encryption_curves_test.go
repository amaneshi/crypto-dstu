//go:build integration

package cms

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITKalynaAdditionalCurves(t *testing.T) {
	const password = "disposable-curve-profile"
	for _, curve := range []struct {
		name   string
		digest asn1.ObjectIdentifier
	}{
		{"DSTU_PB_163", oid.Kupyna256},
		{"DSTU_PB_167", oid.Kupyna256},
		{"DSTU_PB_173", oid.Kupyna256},
		{"DSTU_PB_179", oid.Kupyna256},
		{"DSTU_PB_191", oid.Kupyna256},
		{"DSTU_PB_233", oid.Kupyna256},
		{"DSTU_PB_307", oid.Kupyna256},
		{"DSTU_PB_367", oid.Kupyna256},
		{"DSTU_PB_431", oid.Kupyna512},
	} {
		t.Run(curve.name, func(t *testing.T) {
			senderKey, err := dstu4145.GenerateKey(dstu4145.ParamsByName(curve.name).Curve)
			require.NoError(t, err)
			recipientKey, err := dstu4145.GenerateKey(dstu4145.ParamsByName(curve.name).Curve)
			require.NoError(t, err)
			sender := testiit.CertificateForDigest(t, senderKey, false, curve.digest)
			recipient := testiit.AgreementCertificateForDigest(t, recipientKey, curve.digest)
			protect := func(key *dstu4145.PrivateKey) []byte {
				t.Helper()
				raw, err := keystore.MarshalRawKey(key)
				require.NoError(t, err)
				container, err := keystore.MarshalKey6(
					raw, password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8),
				)
				require.NoError(t, err)
				return container
			}
			senderContainer, recipientContainer := protect(senderKey), protect(recipientKey)
			certificates := [][]byte{sender.Raw, recipient.Raw}
			for _, profile := range []struct {
				name      string
				algorithm asn1.ObjectIdentifier
			}{
				{"kalyna256-cfb", OIDKalyna256CFB}, {"kalyna256-ofb", OIDKalyna256OFB},
			} {
				t.Run(profile.name, func(t *testing.T) {
					for _, size := range []int{1, 33, 65} {
						t.Run(fmt.Sprint(size), func(t *testing.T) {
							content := make([]byte, size)
							for i := range content {
								content[i] = byte(i)
							}
							native := testiit.Invoke(t, testiit.Request{
								Operation: "encrypt", Cipher: profile.name, StaticOriginator: true,
								PrivateKey: senderContainer, Password: password, Certificates: certificates,
								Recipients: [][]byte{recipient.Raw}, Data: content,
							})
							require.True(t, native.OK, native.Error)
							message, err := ParseEnveloped(native.Data)
							require.NoError(t, err)
							require.Equal(t, profile.algorithm, message.Algorithm)
							require.Equal(t, OIDKupynaDH, message.Recipients[0].AgreementAlgorithm)
							require.Len(t, message.Recipients[0].WrappedCEK, 96)
							plaintext, err := DecryptEnveloped(message, recipientKey, recipient, sender)
							require.NoError(t, err)
							require.Equal(t, content, plaintext)
							for _, mode := range []string{"dynamic", "static", "embedded-static"} {
								t.Run(mode, func(t *testing.T) {
									options := EncryptOptions{Algorithm: profile.algorithm}
									if mode != "dynamic" {
										options.OriginatorCertificate = sender
									}
									options.EmbedOriginatorCertificate = mode == "embedded-static"
									encoded, err := EncryptWithOptions(content, []*cert.Certificate{recipient}, senderKey, options)
									require.NoError(t, err)
									trustedInput := certificates
									if mode == "embedded-static" {
										trustedInput = [][]byte{recipient.Raw}
									}
									decrypted := testiit.Invoke(t, testiit.Request{Operation: "decrypt", PrivateKey: recipientContainer,
										Password: password, Certificates: trustedInput, Data: encoded})
									require.True(t, decrypted.OK, decrypted.Error)
									require.Equal(t, content, decrypted.Data)
								})
							}
							if size == 33 {
								bad, err := ParseEnveloped(native.Data)
								require.NoError(t, err)
								bad.Recipients[0].WrappedCEK[95] ^= 1
								plaintext, err := DecryptEnveloped(bad, recipientKey, recipient, sender)
								require.Error(t, err)
								require.Nil(t, plaintext)
								plaintext, err = DecryptEnveloped(message, senderKey, recipient, sender)
								require.Error(t, err)
								require.Nil(t, plaintext)
							}
						})
					}
				})
			}
		})
	}
}
