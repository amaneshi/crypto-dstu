//go:build integration

package cms

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	czo "github.com/amaneshi/crypto-dstu/testdata/czo"
	"github.com/stretchr/testify/require"
)

type iitRequest struct {
	Operation        string   `json:"operation"`
	Data             []byte   `json:"data"`
	Signature        []byte   `json:"signature,omitempty"`
	Detached         bool     `json:"detached,omitempty"`
	Certificates     [][]byte `json:"certificates,omitempty"`
	PrivateKey       []byte   `json:"private_key,omitempty"`
	Password         string   `json:"password,omitempty"`
	Recipients       [][]byte `json:"recipients,omitempty"`
	StaticOriginator bool     `json:"static_originator,omitempty"`
}
type iitResponse struct {
	OK      bool   `json:"ok"`
	Data    []byte `json:"data"`
	Error   string `json:"error"`
	Code    uint32 `json:"code"`
	Policy  string `json:"policy"`
	SDKHash string `json:"sdk_sha256"`
}

func invokeIIT(t *testing.T, req iitRequest) iitResponse {
	t.Helper()
	oracle, sdk := os.Getenv("IIT_ORACLE"), os.Getenv("IIT_SDK_DIR")
	if oracle == "" || sdk == "" {
		t.Skip("set IIT_ORACLE and IIT_SDK_DIR to run independent IIT tests")
	}
	require.True(t, filepath.IsAbs(oracle), "IIT_ORACLE must be absolute")
	input, err := json.Marshal(req)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, oracle, "-sdk", sdk)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	require.NoError(t, ctx.Err(), "IIT timed out: %s", stderr.String())
	var response iitResponse
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &response), "IIT runner failed: %v; stderr: %s; stdout: %s", runErr, stderr.String(), stdout.String())
	require.Equal(t, "offline-no-revocation", response.Policy)
	require.Len(t, response.SDKHash, 64)
	if pin := os.Getenv("IIT_SDK_SHA256"); pin != "" {
		require.Equal(t, strings.ToLower(pin), response.SDKHash)
	}
	if response.OK {
		require.NoError(t, runErr)
	} else {
		require.Error(t, runErr)
		require.NotEmpty(t, response.Error)
		require.Empty(t, response.Data)
	}
	t.Logf("IIT SDK SHA256 %s", response.SDKHash)
	return response
}

// These certificates and keys are generated for each run. No live CA, user key,
// report, or tax-office endpoint participates in these tests.
func makeIITTestCertificate(t *testing.T, key *dstu4145.PrivateKey) *cert.Certificate {
	return testiit.Certificate(t, key, false)
}

func TestIITGOSTHash(t *testing.T) {
	for _, size := range []int{0, 1, 3, 31, 32, 33, 64, 1001} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{0x63}, size)
			h := gost34311.New()
			h.Write(data)
			result := invokeIIT(t, iitRequest{Operation: "hash", Data: data})
			require.True(t, result.OK, result.Error)
			require.Equal(t, h.Sum(nil), result.Data)
		})
	}
}

func TestIITVerifiesGoSignatures(t *testing.T) {
	if os.Getenv("IIT_ORACLE") == "" {
		t.Skip("set IIT_ORACLE and IIT_SDK_DIR")
	}
	key := mustGenerateKey(t)
	c := makeIITTestCertificate(t, key)
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
			content := []byte("crypto-dstu independent IIT test\x00\xff\r\nТест")
			signed, err := Sign(content, key, c, SignOptions{Detached: detached})
			require.NoError(t, err)
			request := iitRequest{Operation: "verify", Data: content, Signature: signed, Detached: detached, Certificates: [][]byte{c.Raw}}
			result := invokeIIT(t, request)
			require.True(t, result.OK, result.Error)
			require.Equal(t, content, result.Data)
			msg, err := VerifySignedRaw(signed, content, []*cert.Certificate{c})
			require.NoError(t, err)
			require.True(t, msg.Signers[0].Valid)
			if detached {
				request.Data = bytes.Repeat([]byte{'X'}, len(content))
			} else {
				request.Signature = bytes.Replace(signed, content, bytes.Repeat([]byte{'X'}, len(content)), 1)
			}
			result = invokeIIT(t, request)
			require.False(t, result.OK, "IIT accepted modified content")
		})
	}
}

const iitTestPassword = "disposable-test-password"

func makeIITIdentity(t *testing.T) ([]byte, *dstu4145.PrivateKey, *cert.Certificate) {
	t.Helper()
	generated := invokeIIT(t, iitRequest{Operation: "generate", Password: iitTestPassword})
	require.True(t, generated.OK, generated.Error)
	pairs, err := keystore.ParsePKCS12(generated.Data, iitTestPassword)
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	key := pairs[0].PrivateKey
	return generated.Data, key, makeIITTestCertificate(t, key)
}

func makeIITKey6(t *testing.T, key *dstu4145.PrivateKey) []byte {
	t.Helper()
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	salt, iv := make([]byte, 32), make([]byte, 8)
	_, err = rand.Read(salt)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)
	encoded, err := keystore.MarshalKey6(raw, iitTestPassword, salt, 1000, iv)
	require.NoError(t, err)
	return encoded
}

func TestIITSignsGoVerifies(t *testing.T) {
	pfx, key, c := makeIITIdentity(t)
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"iit-pfx", pfx}, {"go-key6", makeIITKey6(t, key)},
	} {
		for _, detached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/detached=%t", tc.name, detached), func(t *testing.T) {
				content := []byte("IIT generated signature\x00\xff\r\nТест")
				request := iitRequest{Operation: "sign", Data: content, Detached: detached, PrivateKey: tc.key, Password: iitTestPassword, Certificates: [][]byte{c.Raw}}
				result := invokeIIT(t, request)
				require.True(t, result.OK, result.Error)
				msg, err := VerifySignedRaw(result.Data, content, []*cert.Certificate{c})
				require.NoError(t, err)
				require.Len(t, msg.Signers, 1)
				require.True(t, msg.Signers[0].Valid)
				if !detached {
					require.Equal(t, content, msg.Content)
				}
				modified := bytes.Repeat([]byte{'X'}, len(content))
				signed := result.Data
				if !detached {
					signed = bytes.Replace(signed, content, modified, 1)
				}
				_, err = VerifySignedRaw(signed, modified, []*cert.Certificate{c})
				require.Error(t, err, "Go accepted changed IIT-signed content")
				request.Password = "wrong-test-password"
				require.False(t, invokeIIT(t, request).OK)
			})
		}
	}
}

func TestIITEncryptionBothDirections(t *testing.T) {
	recipientPFX, recipientKey, recipientCert := makeIITIdentity(t)
	senderKey := mustGenerateKey(t)
	senderCert := makeIITTestCertificate(t, senderKey)
	wrongKeyContainer := makeIITKey6(t, senderKey)
	for _, size := range []int{1, 7, 8, 9, 31, 32, 33, 1001} {
		content := bytes.Repeat([]byte("\x00\xff\r\nТест\x01"), size)[:size]
		t.Run(fmt.Sprintf("iit-to-go/%d", size), func(t *testing.T) {
			result := invokeIIT(t, iitRequest{Operation: "encrypt", Data: content, Certificates: [][]byte{senderCert.Raw}, Recipients: [][]byte{senderCert.Raw}})
			require.True(t, result.OK, result.Error)
			msg, err := ParseEnveloped(result.Data)
			require.NoError(t, err)
			plain, err := DecryptEnveloped(msg, senderKey, senderCert)
			require.NoError(t, err)
			require.Equal(t, content, plain)
			if size == 33 {
				plain, err = DecryptEnveloped(msg, recipientKey, senderCert)
				require.Error(t, err)
				require.Empty(t, plain)
				msg.Recipients[0].WrappedCEK[0] ^= 1
				plain, err = DecryptEnveloped(msg, senderKey, senderCert)
				require.Error(t, err)
				require.Empty(t, plain)
			}
		})
		t.Run(fmt.Sprintf("go-to-iit/%d", size), func(t *testing.T) {
			encrypted, err := Encrypt(content, []*cert.Certificate{recipientCert}, senderKey)
			require.NoError(t, err)
			request := iitRequest{Operation: "decrypt", Data: encrypted, PrivateKey: recipientPFX, Password: iitTestPassword, Certificates: [][]byte{recipientCert.Raw, senderCert.Raw}}
			result := invokeIIT(t, request)
			require.True(t, result.OK, result.Error)
			require.Equal(t, content, result.Data)
			if size == 33 {
				request.PrivateKey = wrongKeyContainer
				require.False(t, invokeIIT(t, request).OK)
				request.PrivateKey = recipientPFX
				msg, err := ParseEnveloped(encrypted)
				require.NoError(t, err)
				wrapped := msg.Recipients[0].WrappedCEK
				damaged := bytes.Clone(wrapped)
				damaged[0] ^= 1
				request.Data = bytes.Replace(encrypted, wrapped, damaged, 1)
				require.False(t, invokeIIT(t, request).OK)
			}
		})
	}
}
func TestIITPublicCZOFixture(t *testing.T) {
	caDir := os.Getenv("IIT_TEST_CA_DIR")
	if caDir == "" {
		t.Skip("set IIT_TEST_CA_DIR to the extracted public CZO CA-FULL.zip")
	}
	var certificates [][]byte
	err := filepath.WalkDir(caDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ext := strings.ToLower(filepath.Ext(p))
		if !d.IsDir() && (ext == ".cer" || ext == ".crt") {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			certificates = append(certificates, b)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, certificates)
	data, err := os.ReadFile(czo.Path("cades/DSTU/enveloped/CAdES-BES/test.txt.p7s"))
	require.NoError(t, err)
	result := invokeIIT(t, iitRequest{Operation: "verify", Signature: data, Certificates: certificates})
	require.True(t, result.OK, result.Error)
	msg, err := VerifySignedRaw(data, nil, nil)
	require.NoError(t, err)
	require.True(t, msg.Signers[0].Valid)
	require.Equal(t, msg.Content, result.Data)
}

func TestIITStaticOriginatorCertificates(t *testing.T) {
	recipientPFX, recipientKey, recipientCert := makeIITIdentity(t)
	senderKey := mustGenerateKey(t)
	senderCert := makeIITTestCertificate(t, senderKey)
	senderKey6 := makeIITKey6(t, senderKey)
	content := []byte("static originator interoperability\x00\xff\r\nТест")
	t.Run("iit-to-go", func(t *testing.T) {
		result := invokeIIT(t, iitRequest{Operation: "encrypt", StaticOriginator: true, Data: content, PrivateKey: senderKey6, Password: iitTestPassword, Certificates: [][]byte{senderCert.Raw, recipientCert.Raw}, Recipients: [][]byte{recipientCert.Raw}})
		require.True(t, result.OK, result.Error)
		msg, err := ParseEnveloped(result.Data)
		require.NoError(t, err)
		require.NotNil(t, msg.Recipients[0].OriginatorID)
		plain, err := DecryptEnveloped(msg, recipientKey, recipientCert)
		require.ErrorContains(t, err, "not found")
		require.Empty(t, plain)
		plain, err = DecryptEnveloped(msg, recipientKey, recipientCert, senderCert)
		require.NoError(t, err)
		require.Equal(t, content, plain)
		embedded := replaceEnvelopeOriginator(t, result.Data, nil, senderCert.Raw)
		msg, err = ParseEnveloped(embedded)
		require.NoError(t, err)
		require.Len(t, msg.OriginatorCertificates, 1)
		plain, err = DecryptEnveloped(msg, recipientKey, recipientCert)
		require.NoError(t, err)
		require.Equal(t, content, plain)
	})
	t.Run("go-to-iit", func(t *testing.T) {
		envelope, err := EncryptWithOriginatorCertificate(content, []*cert.Certificate{recipientCert}, senderKey, senderCert)
		require.NoError(t, err)
		request := iitRequest{Operation: "decrypt", Data: envelope, PrivateKey: recipientPFX, Password: iitTestPassword, Certificates: [][]byte{recipientCert.Raw, senderCert.Raw}}
		result := invokeIIT(t, request)
		require.True(t, result.OK, result.Error)
		require.Equal(t, content, result.Data)
		request.Certificates = [][]byte{recipientCert.Raw}
		require.False(t, invokeIIT(t, request).OK)
	})
}

func TestNationalCompressedCertificatesMatchBothCoordinates(t *testing.T) {
	for range 8 {
		makeIITTestCertificate(t, mustGenerateKey(t))
	}
}
