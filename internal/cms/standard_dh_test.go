package cms

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestStandardDHNativeEnvelopes(t *testing.T) {
	for _, degree := range []int{173, 179, 191, 233, 431} {
		t.Run(fmt.Sprint(degree), func(t *testing.T) {
			data, err := os.ReadFile(fmt.Sprintf("testdata/iit-onb-kalyna/DSTU_ONB_%d.json", degree))
			require.NoError(t, err)
			var fixture struct {
				Producer, SDKHash, Curve, WireNote      string
				SenderCertificate, RecipientCertificate []byte
				Samples                                 []struct {
					Cipher   string
					Envelope []byte
				}
			}
			require.NoError(t, json.Unmarshal(data, &fixture))
			require.Equal(t, "475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f", fixture.SDKHash)
			require.Equal(t, fmt.Sprintf("DSTU_ONB_%d", degree), fixture.Curve)
			require.Contains(t, fixture.WireNote, "Unmodified native")
			require.Contains(t, fixture.Producer, "IIT")
			require.Len(t, fixture.Samples, 2)
			sender, err := cert.ParseCertificate(fixture.SenderCertificate)
			require.NoError(t, err)
			recipient, err := cert.ParseCertificate(fixture.RecipientCertificate)
			require.NoError(t, err)
			curve := dstu4145.ParamsByName(fixture.Curve).Curve
			require.True(t, curve.EqualDomain(recipient.PublicKey.Curve))
			d := new(big.Int).Lsh(big.NewInt(1), uint(new(big.Int).SetBytes(curve.N).BitLen()-2))
			d.Add(d, big.NewInt(0x12345))
			key := &dstu4145.PrivateKey{Curve: curve, D: d}
			require.NoError(t, cert.VerifyCertPKMatch(recipient, key))
			content := make([]byte, 65)
			for i := range content {
				content[i] = byte(i)
			}
			seen := make(map[string]bool)
			for _, sample := range fixture.Samples {
				require.False(t, seen[sample.Cipher])
				seen[sample.Cipher] = true
				t.Run(sample.Cipher, func(t *testing.T) {
					require.Contains(t, []string{"kalyna256-cfb", "kalyna256-ofb"}, sample.Cipher)
					original, err := ParseEnveloped(sample.Envelope)
					require.NoError(t, err)
					want := OIDKalyna256CFB
					if sample.Cipher == "kalyna256-ofb" {
						want = OIDKalyna256OFB
					}
					require.Equal(t, want, original.Algorithm)
					plain, err := DecryptEnveloped(original, key, recipient, sender)
					require.ErrorContains(t, err, "unsupported ONB Kupyna agreement")
					require.Nil(t, plain)
					cofactorDER, err := asn1.Marshal(OIDKupynaDH)
					require.NoError(t, err)
					standardDER, err := asn1.Marshal(OIDKupynaStandardDH)
					require.NoError(t, err)
					require.Greater(t, bytes.Count(sample.Envelope, cofactorDER), 0)
					// Explicit test-only reinterpretation of the retained SDK quirk.
					corrected := bytes.ReplaceAll(sample.Envelope, cofactorDER, standardDER)
					parsed, err := ParseEnveloped(corrected)
					require.NoError(t, err)
					plain, err = DecryptEnveloped(parsed, key, recipient, sender)
					require.NoError(t, err)
					require.Equal(t, content, plain)
					wrong := &dstu4145.PrivateKey{Curve: curve, D: new(big.Int).Add(d, big.NewInt(1))}
					plain, err = DecryptEnveloped(parsed, wrong, recipient, sender)
					require.Error(t, err)
					require.Nil(t, plain)
					for i := range parsed.Recipients {
						parsed.Recipients[i].WrappedCEK[32] ^= 1
					}
					plain, err = DecryptEnveloped(parsed, key, recipient, sender)
					require.Error(t, err)
					require.Nil(t, plain)
				})
			}
		})
	}
}

func TestStandardDHRejectsPeerAndProfileSubstitution(t *testing.T) {
	for _, name := range []string{"DSTU_PB_257", "DSTU_ONB_173"} {
		t.Run(name, func(t *testing.T) {
			curve := dstu4145.ParamsByName(name).Curve
			key, err := dstu4145.GenerateKey(curve)
			require.NoError(t, err)
			certificate := testiit.NamedCertificate(t, key)
			encoded, err := EncryptWithOptions([]byte("data"), []*cert.Certificate{certificate}, key, EncryptOptions{Algorithm: OIDKalyna256CFB, AgreementAlgorithm: OIDKupynaStandardDH})
			require.NoError(t, err)
			parsed, err := ParseEnveloped(encoded)
			require.NoError(t, err)
			parsed.Recipients[0].AgreementAlgorithm = OIDKupynaDH
			plain, err := DecryptEnveloped(parsed, key, certificate)
			require.Error(t, err)
			require.Nil(t, plain)
			parsed, err = ParseEnveloped(encoded)
			require.NoError(t, err)
			zero, err := asn1.Marshal(make([]byte, (curve.M+7)/8))
			require.NoError(t, err)
			parsed.Recipients[0].OriginatorPK = zero
			plain, err = DecryptEnveloped(parsed, key, certificate)
			require.ErrorContains(t, err, "prime-order subgroup")
			require.Nil(t, plain)
			for _, options := range []EncryptOptions{
				{Algorithm: OIDGost28147CFB, AgreementAlgorithm: OIDKupynaStandardDH},
				{Algorithm: OIDKalyna256CFB, AgreementAlgorithm: asn1.ObjectIdentifier{1, 2, 3}},
			} {
				output, err := EncryptWithOptions([]byte("data"), []*cert.Certificate{certificate}, key, options)
				require.Error(t, err)
				require.Nil(t, output)
			}
		})
	}
}
