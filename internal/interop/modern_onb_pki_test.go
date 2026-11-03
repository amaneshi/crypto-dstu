//go:build integration

package interop_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/csr"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

func TestIITModernONBPKI(t *testing.T) {
	for _, name := range []string{"DSTU_ONB_173", "DSTU_ONB_179", "DSTU_ONB_191", "DSTU_ONB_233", "DSTU_ONB_431"} {
		t.Run(name, func(t *testing.T) {
			curve := dstu4145.ParamsByName(name).Curve
			d := new(big.Int).Lsh(big.NewInt(1), uint(new(big.Int).SetBytes(curve.N).BitLen()-2))
			d.Add(d, big.NewInt(0x12345))
			key := &dstu4145.PrivateKey{Curve: curve, D: d}
			raw, err := keystore.MarshalRawKey(key)
			require.NoError(t, err)
			container, err := keystore.MarshalKey6(raw, "disposable-modern-pki", bytes.Repeat([]byte{0x53}, 32), 2, bytes.Repeat([]byte{0x49}, 8))
			require.NoError(t, err)
			type sample struct {
				Bits             int
				Certificate, CSR []byte
			}
			var samples []sample
			var sdkHash, opensslVersion string
			for _, profile := range []struct {
				bits              int
				digest, algorithm asn1.ObjectIdentifier
			}{
				{256, oid.Kupyna256, oid.DSTU4145ONBWithKupyna256}, {512, oid.Kupyna512, oid.DSTU4145ONBWithKupyna512},
			} {
				t.Run(fmt.Sprint(profile.bits), func(t *testing.T) {
					certificate := testiit.NamedCertificateForDigest(t, key, profile.digest)
					require.Equal(t, oid.DSTU4145ONBWithGOST34311, certificate.PublicKeyAlgorithm)
					require.Equal(t, profile.algorithm, certificate.SigAlgOID)
					parsed := testiit.Invoke(t, testiit.Request{Operation: "cert-parse", Data: certificate.Raw})
					require.True(t, parsed.OK, parsed.Error)
					signed := testiit.Invoke(t, testiit.Request{Operation: "sign", Digest: fmt.Sprintf("kupyna%d", profile.bits), Detached: true, Data: []byte("modern ONB certificate"), PrivateKey: container, Password: "disposable-modern-pki", Certificates: [][]byte{certificate.Raw}})
					require.True(t, signed.OK, signed.Error)
					verified := testiit.Invoke(t, testiit.Request{Operation: "verify", Detached: true, Data: []byte("modern ONB certificate"), Signature: signed.Data, Certificates: [][]byte{certificate.Raw}})
					require.True(t, verified.OK, verified.Error)
					request, err := csr.Create(&csr.Request{SignatureAlgorithmOID: profile.algorithm, Subject: []csr.AttributeTypeAndValue{{Type: oid.OIDCommonName, Value: "Modern ONB request"}}}, key)
					require.NoError(t, err)
					local, err := csr.Parse(request)
					require.NoError(t, err)
					require.NoError(t, local.Verify())
					_, spki, _, algorithm := testiit.CSRSignatureData(t, request)
					require.Equal(t, profile.algorithm, algorithm)
					require.Equal(t, testiit.CertificateSPKI(t, certificate.Raw), spki, "request SPKI must equal the independently accepted certificate SPKI")
					t.Run("UAPKIC", func(t *testing.T) {
						tool := os.Getenv("MODERN_ONB_UAPKIC_WSL")
						if tool == "" {
							t.Skip("set MODERN_ONB_UAPKIC_WSL for independent signature checks")
						}
						for _, input := range []struct {
							kind string
							data []byte
						}{{"cert", certificate.Raw}, {"csr", request}} {
							path := filepath.Join(t.TempDir(), "public-"+input.kind+".der")
							require.NoError(t, os.WriteFile(path, input.data, 0600))
							wslPath := "/mnt/" + strings.ToLower(filepath.VolumeName(path)[:1]) + strings.ReplaceAll(path[len(filepath.VolumeName(path)):], "\\", "/")
							output, err := exec.Command("wsl.exe", "-d", "Ubuntu", "--exec", tool, input.kind, wslPath).CombinedOutput()
							require.NoError(t, err, "%s", output)
							require.Contains(t, string(output), "UAPKIC modern ONB signature verified")
						}
					})
					if openssl := os.Getenv("PKCS12_OPENSSL"); openssl != "" {
						path := filepath.Join(t.TempDir(), "public-request.der")
						require.NoError(t, os.WriteFile(path, request, 0600))
						output, err := exec.Command(openssl, "req", "-inform", "DER", "-in", path, "-noout", "-subject").CombinedOutput()
						require.NoError(t, err, "%s", output)
						require.Contains(t, string(output), "Modern ONB request")
						version, err := exec.Command(openssl, "version").CombinedOutput()
						require.NoError(t, err)
						opensslVersion = strings.TrimSpace(string(version))
					}
					sdkHash = verified.SDKHash
					samples = append(samples, sample{profile.bits, certificate.Raw, request})
				})
			}
			if directory := os.Getenv("IIT_CAPTURE_MODERN_ONB_PKI_DIR"); directory != "" && !t.Failed() {
				require.NotEmpty(t, os.Getenv("MODERN_ONB_UAPKIC_WSL"))
				require.NotEmpty(t, opensslVersion)
				require.Len(t, samples, 2)
				require.True(t, filepath.IsAbs(directory))
				require.NoError(t, os.MkdirAll(directory, 0700))
				fixture := struct {
					Producer, SDKHash, Curve, OpenSSL, ReferenceCommit, Validation string
					Samples                                                        []sample
				}{"Go ASN.1 and signature generation; independently checked by IIT and UAPKIC", sdkHash, name, opensslVersion, "1996c0fe56dbbc69f5b00d67784a5bc3033b57fe", "Native certificate parsing/key use and identical SPKI; exact TBS/CRI signatures independently verified by unmodified UAPKIC through explicit point-wire transcoding. No issuance or identity trust. Public d=2^(bitlen(n)-2)+0x12345.", samples}
				data, err := json.MarshalIndent(fixture, "", "  ")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(directory, name+".json"), append(data, '\n'), 0600))
			}
		})
	}
}
