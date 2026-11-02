//go:build integration

package ua

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func TestLiveCreateCZOSignatureTimestamp(t *testing.T) {
	if os.Getenv("TSP_LIVE_CREATION") != "1" {
		t.Skip("set explicit public timestamp endpoint and root")
	}
	endpoint := os.Getenv("TSP_PUBLIC_URL")
	require.NotEmpty(t, endpoint)
	rootDER, err := os.ReadFile(os.Getenv("TSP_PUBLIC_ROOT"))
	require.NoError(t, err)
	root, key := testpki.Issue(t, "disposable document root", nil, nil, testpki.CAExtensions(t))
	signer, signKey := testpki.Issue(t, "disposable signer", root, key, nil)
	box := NewBox()
	box.caCerts = []*cert.Certificate{root}
	box.keys = []*keyEntry{{privateKey: signKey, signCert: signer}}
	box.AddTSP(endpoint)
	content := []byte("crypto-dstu public CAdES-T creation interoperability test")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	signed, err := box.SignDocumentWithContext(ctx, content, SignOptions{NoTax: true, Timestamp: &TimestampSignOptions{TSARoots: [][]byte{rootDER}}})
	require.NoError(t, err)
	result, err := box.UnsignDocumentWithOptions(ctx, signed, nil, VerificationOptions{TimestampPolicy: TimestampRequireSignature, TSARoots: [][]byte{rootDER}})
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	require.Len(t, result.Timestamps, 1)
	require.True(t, result.Timestamps[0].Valid)
	t.Logf("created and verified CAdES-T: TSA=%s time=%s", result.Timestamps[0].TSA.CommonName, result.Timestamps[0].Time.UTC().Format(time.RFC3339Nano))
	if directory := os.Getenv("TSP_CREATION_CAPTURE"); directory != "" {
		require.NoError(t, os.MkdirAll(directory, 0700))
		for name, value := range map[string][]byte{"document.cms": signed, "content.txt": content, "document-root.cer": root.Raw, "tsa-root.cer": rootDER} {
			require.NoError(t, os.WriteFile(filepath.Join(directory, name), value, 0600))
		}
		metadata, err := json.MarshalIndent(map[string]any{"validatedAt": result.Timestamps[0].Time, "endpoint": endpoint, "description": "Public test bytes and disposable document key. No private key retained; timestamp creation and roundtrip verification; revocation not checked."}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(directory, "metadata.json"), metadata, 0600))
	}
}
