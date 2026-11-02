//go:build integration

package interop_test

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
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

func TestIITKupyna512HashSigning(t *testing.T) {
	key, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_431").Curve)
	require.NoError(t, err)
	certificate := testiit.CertificateForDigest(t, key, false, oid.Kupyna512)
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	const password = "disposable-512-test"
	container, err := keystore.MarshalKey6(raw, password, bytes.Repeat([]byte{0x53}, 32), 1000, bytes.Repeat([]byte{0x49}, 8))
	require.NoError(t, err)
	for _, contentCase := range []struct {
		name    string
		content []byte
	}{
		{"binary", []byte("native Kupyna512 signing test\x00\xff\r\nТест")},
		{"empty", []byte{}},
		{"multiple blocks", bytes.Repeat([]byte{0xa5}, 129)},
	} {
		t.Run(contentCase.name, func(t *testing.T) {
			content := contentCase.content
			modes := []bool{false, true}
			if len(content) == 0 {
				modes = []bool{true}
			}
			for _, detached := range modes {
				t.Run(map[bool]string{false: "attached", true: "detached"}[detached], func(t *testing.T) {
					signed := testiit.Invoke(t, testiit.Request{
						Operation: "sign", Digest: "kupyna512", Detached: detached, PrivateKey: container,
						Password: password, Certificates: [][]byte{certificate.Raw}, Data: content,
					})
					require.True(t, signed.OK, signed.Error)
					require.Equal(t, !detached, testiit.HasEmbeddedContent(t, signed.Data))
					require.Equal(t, oid.Kupyna512, testiit.SignerDigest(t, signed.Data))
					require.Equal(t, []asn1.ObjectIdentifier{oid.Kupyna512}, testiit.DigestSet(t, signed.Data))
					message, err := cms.VerifySignedRaw(signed.Data, content, []*cert.Certificate{certificate})
					require.NoError(t, err)
					if !detached {
						require.True(t, bytes.Equal(content, message.Content))
					}
					verified := testiit.Invoke(t, testiit.Request{
						Operation: "verify", Detached: detached, Signature: signed.Data, Data: content, Certificates: [][]byte{certificate.Raw},
					})
					require.True(t, verified.OK, verified.Error)
					require.True(t, bytes.Equal(content, verified.Data))
					if directory := os.Getenv("IIT_CAPTURE_512_DIR"); directory != "" && contentCase.name == "binary" {
						require.True(t, filepath.IsAbs(directory), "capture directory must be explicit and absolute")
						require.NoError(t, os.MkdirAll(directory, 0700))
						write := func(name string, data []byte) {
							require.NoError(t, os.WriteFile(filepath.Join(directory, name), data, 0600))
						}
						write(map[bool]string{false: "attached.cms", true: "detached.cms"}[detached], signed.Data)
						if !detached {
							write("signer.cer", certificate.Raw)
							write("content.bin", content)
							metadata, err := json.MarshalIndent(map[string]any{
								"producer": "IIT EUSignCP.dll", "sdk_sha256": signed.SDKHash,
								"profile": "DSTU4145 PB431 / Kupyna-512", "private_key_retained": false,
								"purpose": "public disposable-key interoperability vector; no trust or revocation assertion",
							}, "", "  ")
							require.NoError(t, err)
							write("manifest.json", append(metadata, '\n'))
						}
					}
				})
			}
		})
	}
}
