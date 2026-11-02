//go:build integration

package interop_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/testiit"
	"crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

type capturedCZO struct {
	Time                                                          time.Time
	SDKHash                                                       string
	Document, Control, Content, Signer, TSA, Root, Request, Token []byte
}

func readCapturedCZO(t testing.TB) capturedCZO {
	t.Helper()
	directory := filepath.Join("testdata", "iit-czo-cades-t")
	metadata, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	require.NoError(t, err)
	var manifest struct {
		ValidatedAt time.Time
		SDKSHA256   string
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
	return capturedCZO{manifest.ValidatedAt, manifest.SDKSHA256, read("document.cms"), read("control.cms"), read("content.bin"), read("signer.cer"), read("tsa.cer"), read("tsa-root.cer"), read("request.der"), read("token.der")}
}

func TestCapturedIITCZOInGo(t *testing.T) {
	f := readCapturedCZO(t)
	signer, err := cert.ParseCertificate(f.Signer)
	require.NoError(t, err)
	root, err := cert.ParseCertificate(f.Root)
	require.NoError(t, err)
	require.NoError(t, cert.VerifyCertAt(signer, signer, f.Time))
	message, err := cms.VerifySignedRaw(f.Document, nil, nil)
	require.NoError(t, err)
	require.Equal(t, f.Content, message.Content)
	require.Equal(t, f.Signer, message.Signers[0].Certificate.Raw)
	signature, err := message.SignatureBytes(0)
	require.NoError(t, err)
	tokens, err := message.SignatureTimestampTokens(0)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	require.Equal(t, f.Token, tokens[0])
	var request tsp.Request
	rest, err := asn1.Unmarshal(f.Request, &request)
	require.NoError(t, err)
	require.Empty(t, rest)
	verified, err := tsp.VerifyResponse(&tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: f.Token}}, &request, []*cert.Certificate{root}, f.Time)
	require.NoError(t, err)
	require.Equal(t, f.TSA, verified.TSA.Raw)
	_, err = tsp.VerifySignatureTimestamp(f.Token, signature, []*cert.Certificate{root}, f.Time)
	require.NoError(t, err)
	control, err := cms.VerifySignedRaw(f.Control, nil, nil)
	require.NoError(t, err)
	controlSignature, err := control.SignatureBytes(0)
	require.NoError(t, err)
	require.Equal(t, signature, controlSignature)
}

func TestIITCapturedCZOSignatureTimestamp(t *testing.T) {
	f := readCapturedCZO(t)
	request := testiit.Request{Operation: "verify", Data: f.Content, Signature: f.Control, Certificates: [][]byte{f.Signer, f.TSA, f.Root}}
	baseline := testiit.Invoke(t, request)
	require.True(t, baseline.OK, baseline.Error)
	require.Equal(t, f.Content, baseline.Data)
	request.RequireTimestamp = true
	require.False(t, testiit.Invoke(t, request).OK, "a claimed time is insufficient")
	request.Signature = f.Document
	positive := testiit.Invoke(t, request)
	require.True(t, positive.OK, positive.Error)
	require.Equal(t, f.Content, positive.Data)
	t.Logf("captured using SDK=%s; verified using SDK=%s", f.SDKHash, positive.SDKHash)
	parsed, err := cms.ParseSigned(f.Token)
	require.NoError(t, err)
	signature, err := parsed.SignatureBytes(0)
	require.NoError(t, err)
	altered := bytes.Clone(f.Token)
	position := bytes.Index(altered, signature)
	require.GreaterOrEqual(t, position, 0)
	altered[position] ^= 1
	invalid, err := cms.AttachSignatureTimestamp(f.Control, altered)
	require.NoError(t, err)
	request.Signature = invalid
	negative := testiit.Invoke(t, request)
	require.False(t, negative.OK, "IIT accepted a corrupt CZO timestamp")
	require.Empty(t, negative.Data)
	// A separately valid public token for different data must not satisfy binding.
	wrongToken, err := os.ReadFile(filepath.Join("..", "tsp", "testdata", "czo-live", "token.der"))
	require.NoError(t, err)
	root, err := cert.ParseCertificate(f.Root)
	require.NoError(t, err)
	info, err := tsp.ParseTSTInfo(wrongToken)
	require.NoError(t, err)
	_, err = tsp.VerifyImprint(wrongToken, info.MessageImprint, nil, []*cert.Certificate{root}, f.Time)
	require.NoError(t, err, "negative-control token must have a valid TSA signature/path")
	request.Signature, err = cms.AttachSignatureTimestamp(f.Control, wrongToken)
	require.NoError(t, err)
	negative = testiit.Invoke(t, request)
	require.False(t, negative.OK, "IIT accepted a timestamp over a different imprint")
	require.Empty(t, negative.Data)
}
