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

func TestIITKalynaEncryptionProfiles(t *testing.T) {
	const password = "disposable-envelope"
	generated := testiit.Invoke(t, testiit.Request{Operation: "generate", KeyFamily: "kupyna", KeyBits: 257, Password: password})
	require.True(t, generated.OK, generated.Error)
	pairs, err := keystore.ParsePKCS12(generated.Data, password)
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	senderKey := pairs[0].PrivateKey
	sender := testiit.CertificateForDigest(t, senderKey, false, oid.Kupyna256)
	key, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_257").Curve)
	require.NoError(t, err)
	recipient := testiit.AgreementCertificateForDigest(t, key, oid.Kupyna256)
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	container, err := keystore.MarshalKey6(raw, password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
	require.NoError(t, err)
	certificates := [][]byte{sender.Raw, recipient.Raw}
	for _, profile := range []struct {
		name      string
		algorithm asn1.ObjectIdentifier
	}{
		{"kalyna256-cfb", OIDKalyna256CFB}, {"kalyna256-ofb", OIDKalyna256OFB},
	} {
		t.Run(profile.name, func(t *testing.T) {
			for _, size := range []int{1, 31, 32, 33, 63, 64, 65, 129} {
				t.Run(fmt.Sprint(size), func(t *testing.T) {
					content := make([]byte, size)
					for i := range content {
						content[i] = byte(i)
					}
					encrypted := testiit.Invoke(t, testiit.Request{
						Operation: "encrypt", Cipher: profile.name, StaticOriginator: true, PrivateKey: generated.Data,
						Password: password, Certificates: certificates, Recipients: [][]byte{recipient.Raw}, Data: content,
					})
					require.True(t, encrypted.OK, encrypted.Error)
					message, err := ParseEnveloped(encrypted.Data)
					require.NoError(t, err)
					require.Equal(t, profile.algorithm, message.Algorithm)
					require.Equal(t, OIDKupynaDH, message.Recipients[0].AgreementAlgorithm)
					require.Len(t, message.Recipients[0].WrappedCEK, 96)
					plaintext, err := DecryptEnveloped(message, key, recipient, sender)
					require.NoError(t, err)
					require.Equal(t, content, plaintext)
					if size == 33 {
						for _, offset := range []int{0, 31, 63, 95} {
							corrupt, err := ParseEnveloped(encrypted.Data)
							require.NoError(t, err)
							corrupt.Recipients[0].WrappedCEK[offset] ^= 1
							plaintext, err := DecryptEnveloped(corrupt, key, recipient, sender)
							require.Error(t, err)
							require.Nil(t, plaintext)
						}
						plaintext, err := DecryptEnveloped(message, senderKey, recipient, sender)
						require.Error(t, err)
						require.Nil(t, plaintext)
					}
					for _, static := range []bool{false, true} {
						t.Run(map[bool]string{false: "dynamic", true: "static"}[static], func(t *testing.T) {
							options := EncryptOptions{Algorithm: profile.algorithm}
							if static {
								options.OriginatorCertificate = sender
							}
							encoded, err := EncryptWithOptions(content, []*cert.Certificate{recipient}, senderKey, options)
							require.NoError(t, err)
							parsed, err := ParseEnveloped(encoded)
							require.NoError(t, err)
							plaintext, err := DecryptEnveloped(parsed, key, recipient, sender)
							require.NoError(t, err)
							require.Equal(t, content, plaintext)
							decrypted := testiit.Invoke(t, testiit.Request{
								Operation: "decrypt", PrivateKey: container, Password: password, Certificates: certificates, Data: encoded,
							})
							require.True(t, decrypted.OK, decrypted.Error)
							require.Equal(t, content, decrypted.Data)
						})
					}
				})
			}
		})
	}
}
