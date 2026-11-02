//go:build integration

package interop_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/oid"
	"crypto-dstu/internal/testiit"
	"crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestIITLiveCZOSignatureTimestamp(t *testing.T) {
	if os.Getenv("IIT_LIVE_TSP") != "1" {
		t.Skip("set IIT_LIVE_TSP=1 and explicit public TSA endpoint/root")
	}
	generated := testiit.Invoke(t, testiit.Request{Operation: "generate", Password: "disposable-live-timestamp"})
	require.True(t, generated.OK, generated.Error)
	pairs, err := keystore.ParsePKCS12(generated.Data, "disposable-live-timestamp")
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	signer := testiit.Certificate(t, pairs[0].PrivateKey, false)
	rootDER, err := os.ReadFile(os.Getenv("TSP_PUBLIC_ROOT"))
	require.NoError(t, err)
	root, err := cert.ParseCertificate(rootDER)
	require.NoError(t, err)
	endpoint := os.Getenv("TSP_PUBLIC_URL")
	require.NotEmpty(t, endpoint)
	content := []byte("public CZO timestamp / native IIT interoperability test")
	plain, err := cms.Sign(content, pairs[0].PrivateKey, signer, cms.SignOptions{})
	require.NoError(t, err)
	control := testiit.Request{Operation: "verify", Data: content, Signature: plain, Certificates: [][]byte{signer.Raw}}
	require.True(t, testiit.Invoke(t, control).OK, "IIT must accept the untimestamped control first")
	message, err := cms.ParseSigned(plain)
	require.NoError(t, err)
	signature, err := message.SignatureBytes(0)
	require.NoError(t, err)
	hash, err := tsp.HashData(signature, oid.GOST34311)
	require.NoError(t, err)
	request, err := tsp.NewRequest(hash, oid.GOST34311)
	require.NoError(t, err)
	requestDER, err := request.Marshal()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, err := tsp.NewClient(endpoint).SendContext(ctx, requestDER)
	require.NoError(t, err)
	verified, err := tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now())
	require.NoError(t, err)
	token, err := response.Token()
	require.NoError(t, err)
	document, err := cms.AttachSignatureTimestamp(plain, token)
	require.NoError(t, err)
	control.Signature = document
	control.RequireTimestamp = true
	control.Certificates = append(control.Certificates, rootDER, verified.TSA.Raw)
	result := testiit.Invoke(t, control)
	t.Logf("CZO TSA algorithm=%s, native acceptance=%v error=%s", verified.TSA.SigAlgOID, result.OK, result.Error)
	require.True(t, result.OK, result.Error)
	require.Equal(t, content, result.Data)
	if directory := os.Getenv("IIT_TSP_CAPTURE"); directory != "" {
		require.NoError(t, os.MkdirAll(directory, 0700))
		for name, data := range map[string][]byte{"document.cms": document, "control.cms": plain, "content.bin": content, "signer.cer": signer.Raw, "tsa.cer": verified.TSA.Raw, "tsa-root.cer": rootDER, "request.der": requestDER, "token.der": token} {
			require.NoError(t, os.WriteFile(filepath.Join(directory, name), data, 0600))
		}
		metadata, err := json.MarshalIndent(map[string]any{"validatedAt": verified.Info.GenTime, "endpoint": endpoint, "sdkSHA256": result.SDKHash, "certificateArchive": "https://czo.gov.ua/download/certificates_test/CA-FULL.zip", "description": "Public content, disposable IIT key, Go CMS and live CZO signature timestamp; private key not retained; offline-no-revocation native verification only"}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(directory, "metadata.json"), metadata, 0600))
	}
}
