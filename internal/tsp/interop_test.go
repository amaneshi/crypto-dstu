//go:build integration

package tsp_test

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestCapturedCZOTimestamp(t *testing.T) {
	directory := filepath.Join("testdata", "czo-live")
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	require.NoError(t, err)
	var manifest struct {
		ValidatedAt time.Time
		Files       map[string]struct {
			SHA256 string
			Bytes  int
		}
	}
	require.NoError(t, json.Unmarshal(data, &manifest))
	read := func(name string) []byte {
		t.Helper()
		der, err := os.ReadFile(filepath.Join(directory, name))
		require.NoError(t, err)
		sum := sha256.Sum256(der)
		require.Equal(t, manifest.Files[name].SHA256, hex.EncodeToString(sum[:]))
		require.Len(t, der, manifest.Files[name].Bytes)
		return der
	}
	root, err := cert.ParseCertificate(read("root.cer"))
	require.NoError(t, err)
	var request tsp.Request
	rest, err := asn1.Unmarshal(read("request.der"), &request)
	require.NoError(t, err)
	require.Empty(t, rest)
	token := read("token.der")
	verified, err := tsp.VerifyResponse(&tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: token}}, &request, []*cert.Certificate{root}, manifest.ValidatedAt)
	require.NoError(t, err)
	require.Len(t, verified.Chain, 2)
	nonce := new(big.Int).Add(request.Nonce, big.NewInt(1))
	_, err = tsp.VerifyImprint(token, request.MessageImprint, nonce, []*cert.Certificate{root}, manifest.ValidatedAt)
	require.Error(t, err)
}

func TestCZOExampleSignatureTimestamps(t *testing.T) {
	for _, profile := range []string{"DSTU", "DSTU-7564"} {
		t.Run(profile, func(t *testing.T) {
			directory := filepath.Join("testdata", "czo-examples", profile)
			metadata, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
			require.NoError(t, err)
			var manifest struct {
				ValidatedAt time.Time
				Files       map[string]struct {
					SHA256 string
					Bytes  int
				}
			}
			require.NoError(t, json.Unmarshal(metadata, &manifest))
			read := func(name string) []byte {
				t.Helper()
				der, err := os.ReadFile(filepath.Join(directory, name))
				require.NoError(t, err)
				sum := sha256.Sum256(der)
				require.Equal(t, manifest.Files[name].SHA256, hex.EncodeToString(sum[:]))
				require.Len(t, der, manifest.Files[name].Bytes)
				return der
			}
			root, err := cert.ParseCertificate(read("root.cer"))
			require.NoError(t, err)
			var chain []asn1.RawValue
			rest, err := asn1.Unmarshal(read("discovery.der"), &chain)
			require.NoError(t, err)
			require.Empty(t, rest)
			var discovery []*cert.Certificate
			for _, raw := range chain {
				c, err := cert.ParseCertificate(raw.FullBytes)
				require.NoError(t, err)
				discovery = append(discovery, c)
			}
			require.NotEmpty(t, read("tsa.cer"))
			message, err := cms.ParseSigned(read("document.cms"))
			require.NoError(t, err)
			tokens, err := message.SignatureTimestampTokens(0)
			require.NoError(t, err)
			require.NotEmpty(t, tokens)
			signature, err := message.SignatureBytes(0)
			require.NoError(t, err)
			for _, token := range tokens {
				verified, err := tsp.VerifySignatureTimestamp(token, signature, []*cert.Certificate{root}, manifest.ValidatedAt, discovery...)
				require.NoError(t, err)
				require.Equal(t, read("tsa.cer"), verified.TSA.Raw)
				changed := append([]byte(nil), signature...)
				changed[0] ^= 1
				_, err = tsp.VerifySignatureTimestamp(token, changed, []*cert.Certificate{root}, manifest.ValidatedAt, discovery...)
				require.Error(t, err)
				_, err = tsp.VerifySignatureTimestamp(token, signature, nil, manifest.ValidatedAt, discovery...)
				require.Error(t, err, "discovery certificates cannot become trust roots")
			}
		})
	}
}

func TestCapturedCreatedCZOTimestamp(t *testing.T) {
	directory := filepath.Join("testdata", "created-cades-t")
	metadata, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	require.NoError(t, err)
	var manifest struct {
		ValidatedAt time.Time
		Files       map[string]struct {
			SHA256 string
			Bytes  int
		}
	}
	require.NoError(t, json.Unmarshal(metadata, &manifest))
	read := func(name string) []byte {
		t.Helper()
		der, err := os.ReadFile(filepath.Join(directory, name))
		require.NoError(t, err)
		sum := sha256.Sum256(der)
		require.Equal(t, manifest.Files[name].SHA256, hex.EncodeToString(sum[:]))
		require.Len(t, der, manifest.Files[name].Bytes)
		return der
	}
	documentRoot, err := cert.ParseCertificate(read("document-root.cer"))
	require.NoError(t, err)
	tsaRoot, err := cert.ParseCertificate(read("tsa-root.cer"))
	require.NoError(t, err)
	message, err := cms.VerifySignedRaw(read("document.cms"), nil, nil)
	require.NoError(t, err)
	require.Equal(t, read("content.txt"), message.Content)
	require.NoError(t, cert.VerifyCertAt(documentRoot, documentRoot, manifest.ValidatedAt))
	require.NoError(t, cert.VerifyCertAt(message.Signers[0].Certificate, documentRoot, manifest.ValidatedAt))
	signature, err := message.SignatureBytes(0)
	require.NoError(t, err)
	tokens, err := message.SignatureTimestampTokens(0)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	_, err = tsp.VerifySignatureTimestamp(tokens[0], signature, []*cert.Certificate{tsaRoot}, manifest.ValidatedAt)
	require.NoError(t, err)
}
