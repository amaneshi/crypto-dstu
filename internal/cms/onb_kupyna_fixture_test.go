package cms

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/stretchr/testify/require"
)

func TestONBKupynaNativeFixtures(t *testing.T) {
	for _, degree := range []int{173, 179, 191, 233, 431} {
		t.Run(fmt.Sprint(degree), func(t *testing.T) {
			data, err := os.ReadFile(fmt.Sprintf("testdata/iit-onb-kupyna/DSTU_ONB_%d.json", degree))
			require.NoError(t, err)
			var fixture struct {
				Producer, SDKHash, Curve, WireNote string
				Certificate, Content               []byte
				Samples                            []struct {
					Bits      int
					Detached  bool
					Signature []byte
				}
			}
			require.NoError(t, json.Unmarshal(data, &fixture))
			require.Equal(t, "475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f", fixture.SDKHash)
			require.Equal(t, fmt.Sprintf("DSTU_ONB_%d", degree), fixture.Curve)
			require.NotEmpty(t, fixture.Producer)
			require.Contains(t, fixture.WireNote, "Unmodified native")
			require.Len(t, fixture.Samples, 4)
			certificate, err := cert.ParseCertificate(fixture.Certificate)
			require.NoError(t, err)
			require.True(t, certificate.PublicKey.Curve.IsONB())
			require.Equal(t, degree, certificate.PublicKey.Curve.M)
			seen := make(map[string]bool)
			for _, sample := range fixture.Samples {
				name := fmt.Sprintf("%d/detached=%t", sample.Bits, sample.Detached)
				require.False(t, seen[name], "duplicate profile coverage")
				seen[name] = true
				t.Run(name, func(t *testing.T) {
					pb, onb, digest := oid.DSTU4145WithKupyna256, oid.DSTU4145ONBWithKupyna256, oid.Kupyna256
					if sample.Bits == 512 {
						pb, onb, digest = oid.DSTU4145WithKupyna512, oid.DSTU4145ONBWithKupyna512, oid.Kupyna512
					}
					require.Contains(t, []int{256, 512}, sample.Bits)
					require.Equal(t, pb, testiit.SignerSignatureAlgorithm(t, sample.Signature))
					require.Equal(t, digest, testiit.SignerDigest(t, sample.Signature))
					require.Equal(t, !sample.Detached, testiit.HasEmbeddedContent(t, sample.Signature))
					// Preserve strict basis binding even for this known provider quirk.
					_, err := VerifySignedRaw(sample.Signature, fixture.Content, nil)
					require.ErrorContains(t, err, "signature algorithm")
					pbDER, err := asn1.Marshal(pb)
					require.NoError(t, err)
					onbDER, err := asn1.Marshal(onb)
					require.NoError(t, err)
					require.Equal(t, 1, bytes.Count(sample.Signature, pbDER))
					// Only the test adapter changes this unsigned algorithm identifier.
					corrected := bytes.Replace(sample.Signature, pbDER, onbDER, 1)
					_, err = VerifySignedRaw(corrected, fixture.Content, nil)
					require.NoError(t, err, "independently generated native signature")
					corrupt, err := ParseSigned(bytes.Clone(corrected))
					require.NoError(t, err)
					corrupt.rawSigners[0].Signature[0] ^= 1
					require.Error(t, VerifySigned(corrupt, fixture.Content, nil), "changed native signature must fail")
					changed := bytes.Repeat([]byte{'X'}, len(fixture.Content))
					if !sample.Detached {
						corrected = bytes.Replace(corrected, fixture.Content, changed, 1)
					}
					_, err = VerifySignedRaw(corrected, changed, nil)
					require.Error(t, err)
				})
			}
		})
	}
}
