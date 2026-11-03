package testvectors_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/csr"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestModernONBPKIFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/modern-onb-pki/*.json")
	require.NoError(t, err)
	require.Len(t, files, 5)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			var fixture struct {
				SDKHash, Curve, ReferenceCommit, OpenSSL string
				Samples                                  []struct {
					Bits             int
					Certificate, CSR []byte
				}
			}
			require.NoError(t, json.Unmarshal(data, &fixture))
			require.Equal(t, "475539dd6b01015e73cf3d143783c3f164c3f9db1e92e724c6f6493f086d9f4f", fixture.SDKHash)
			require.Equal(t, "1996c0fe56dbbc69f5b00d67784a5bc3033b57fe", fixture.ReferenceCommit)
			require.Contains(t, fixture.OpenSSL, "OpenSSL")
			require.Len(t, fixture.Samples, 2)
			for i, sample := range fixture.Samples {
				t.Run(big.NewInt(int64(sample.Bits)).String(), func(t *testing.T) {
					require.Equal(t, []int{256, 512}[i], sample.Bits)
					algorithm, pbAlgorithm := oid.DSTU4145ONBWithKupyna256, oid.DSTU4145WithKupyna256
					if sample.Bits == 512 {
						algorithm, pbAlgorithm = oid.DSTU4145ONBWithKupyna512, oid.DSTU4145WithKupyna512
					}
					c, err := cert.ParseCertificate(sample.Certificate)
					require.NoError(t, err)
					require.True(t, c.PublicKey.Curve.EqualDomain(dstu4145.ParamsByName(fixture.Curve).Curve))
					require.Equal(t, oid.DSTU4145ONBWithGOST34311, c.PublicKeyAlgorithm)
					require.Equal(t, algorithm, c.SigAlgOID)
					at := c.NotBefore.Add(time.Hour)
					require.NoError(t, cert.VerifyCertAt(c, c, at))
					request, err := csr.Parse(sample.CSR)
					require.NoError(t, err)
					require.NoError(t, request.Verify())
					require.Equal(t, algorithm, request.SignatureAlgOID)
					cri, spki, _, _ := testiit.CSRSignatureData(t, sample.CSR)
					require.Equal(t, testiit.CertificateSPKI(t, c.Raw), spki)
					wrongKey := &dstu4145.PrivateKey{Curve: c.PublicKey.Curve, D: big.NewInt(3)}
					issuer := *c
					issuer.PublicKey = wrongKey.Public()
					require.Error(t, cert.VerifyCertAt(c, &issuer, at))
					issuer.PublicKey = (&dstu4145.PrivateKey{Curve: dstu4145.ParamsByName("DSTU_PB_257").Curve, D: big.NewInt(3)}).Public()
					require.ErrorContains(t, cert.VerifyCertAt(c, &issuer, at), "basis differ")
					changed := *c
					changed.TBSRaw = bytes.Clone(c.TBSRaw)
					changed.TBSRaw[len(changed.TBSRaw)-1] ^= 1
					require.Error(t, cert.VerifyCertAt(&changed, c, at))
					changed = *c
					changed.Signature = bytes.Clone(c.Signature)
					changed.Signature[len(changed.Signature)-1] ^= 1
					require.Error(t, cert.VerifyCertAt(&changed, c, at))
					changed = *c
					changed.SigAlgOID = pbAlgorithm
					require.Error(t, cert.VerifyCertAt(&changed, c, at))
					alteredRequest := *request
					alteredRequest.CRIRaw = bytes.Clone(cri)
					alteredRequest.CRIRaw[len(cri)-1] ^= 1
					require.Error(t, alteredRequest.Verify())
					alteredRequest = *request
					alteredRequest.SignatureAlgOID = pbAlgorithm
					require.ErrorContains(t, alteredRequest.Verify(), "curve basis")
					alteredRequest = *request
					alteredRequest.SignatureBytes = bytes.Clone(request.SignatureBytes)
					alteredRequest.SignatureBytes[len(alteredRequest.SignatureBytes)-1] ^= 1
					require.Error(t, alteredRequest.Verify())
					// The two certificate signature identifiers must agree even before verification.
					encoded, err := asn1.Marshal(algorithm)
					require.NoError(t, err)
					wrongEncoded, err := asn1.Marshal(pbAlgorithm)
					require.NoError(t, err)
					mismatch := bytes.Clone(c.Raw)
					offset := bytes.LastIndex(mismatch, encoded)
					require.Positive(t, offset)
					require.Equal(t, len(encoded), len(wrongEncoded))
					copy(mismatch[offset:], wrongEncoded)
					invalid, err := cert.ParseCertificate(mismatch)
					require.Error(t, err)
					require.Nil(t, invalid)
					// Both certificate identifiers relabeled to PB still fail against the ONB issuer.
					relabeled := bytes.ReplaceAll(c.Raw, encoded, wrongEncoded)
					invalid, err = cert.ParseCertificate(relabeled)
					require.NoError(t, err)
					require.Error(t, cert.VerifyCertAt(invalid, c, at))
					// Replacing the SPKI identifier with an unvalidated modern profile must fail.
					// Re-encode nested lengths after replacing the OID.
					var public struct {
						Algorithm struct {
							OID        asn1.ObjectIdentifier
							Parameters asn1.RawValue
						}
						Key asn1.BitString
					}
					_, err = asn1.Unmarshal(spki, &public)
					require.NoError(t, err)
					public.Algorithm.OID = algorithm
					modernSPKI, err := asn1.Marshal(public)
					require.NoError(t, err)
					var fields []asn1.RawValue
					_, err = asn1.Unmarshal(cri, &fields)
					require.NoError(t, err)
					fields[2] = asn1.RawValue{FullBytes: modernSPKI}
					badCRI, err := asn1.Marshal(fields)
					require.NoError(t, err)
					var outer []asn1.RawValue
					_, err = asn1.Unmarshal(sample.CSR, &outer)
					require.NoError(t, err)
					outer[0] = asn1.RawValue{FullBytes: badCRI}
					badCSR, err := asn1.Marshal(outer)
					require.NoError(t, err)
					bad, err := csr.Parse(badCSR)
					require.Error(t, err)
					require.Nil(t, bad)
					t.Run("UAPKIC", func(t *testing.T) {
						tool := os.Getenv("MODERN_ONB_UAPKIC_WSL")
						if tool == "" {
							t.Skip("set MODERN_ONB_UAPKIC_WSL for independent replay")
						}
						for _, input := range []struct {
							kind string
							data []byte
						}{{"cert", c.Raw}, {"csr", sample.CSR}} {
							path := filepath.Join(t.TempDir(), "public.der")
							wslPath := "/mnt/" + strings.ToLower(filepath.VolumeName(path)[:1]) + strings.ReplaceAll(path[len(filepath.VolumeName(path)):], "\\", "/")
							require.NoError(t, os.WriteFile(path, input.data, 0600))
							output, err := exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, input.kind, wslPath).CombinedOutput()
							require.NoError(t, err, "%s", output)
							corrupted := bytes.Clone(input.data)
							corrupted[len(corrupted)-1] ^= 1
							require.NoError(t, os.WriteFile(path, corrupted, 0600))
							output, err = exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, input.kind, wslPath).CombinedOutput()
							require.Error(t, err, "%s", output)
							// A valid DER subject mutation must also fail the exact-data verification.
							mutated := bytes.Replace(input.data, []byte("Modern ONB request"), []byte("Modern ONB requesu"), 1)
							if input.kind == "cert" {
								mutated = bytes.Replace(input.data, []byte("local interoperability"), []byte("local interoperabilitz"), 1)
							}
							require.NotEqual(t, input.data, mutated)
							require.NoError(t, os.WriteFile(path, mutated, 0600))
							output, err = exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, input.kind, wslPath).CombinedOutput()
							require.Error(t, err, "%s", output)
						}
					})
				})
			}
		})
	}
}
