package main

import (
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/testtimestamp"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestSignTimestampCLIControlsOutput(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", root, rootKey, nil)
	tsa, tsaKey := testpki.Issue(t, "TSA", root, rootKey, testtimestamp.Extensions(t))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "body", 400)
			return
		}
		var request tsp.Request
		rest, err := asn1.Unmarshal(body, &request)
		if err != nil || len(rest) != 0 {
			http.Error(w, "request", 400)
			return
		}
		token := testtimestamp.Token(t, nil, tsa, tsaKey, func(i *tsp.TSTInfo) {
			i.MessageImprint = request.MessageImprint
			i.Nonce = request.Nonce
			if r.URL.Path == "/bad" {
				i.Nonce = new(big.Int).Add(i.Nonce, big.NewInt(1))
			}
		})
		reply, err := asn1.Marshal(tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: token}})
		if err != nil {
			http.Error(w, "encode", 500)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(reply)
	}))
	defer server.Close()
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		return path
	}
	keyDER, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	keyPath, certPath, rootPath := write("key.der", keyDER), write("leaf.cer", leaf.Raw), write("tsa-root.cer", root.Raw)
	content := []byte("public local test document")
	input := write("input.txt", content)
	for _, tc := range []struct {
		name                  string
		bad, crypt, omitTrust bool
		digest                string
	}{
		{name: "valid"},
		{name: "encrypted Kupyna256", crypt: true, digest: "kupyna256"},
		{name: "Kupyna512", digest: "kupyna512"},
		{name: "bad nonce", bad: true, digest: "kupyna256"},
		{name: "missing TSA trust", omitTrust: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output.cms")
			endpoint := server.URL
			if tc.bad {
				endpoint += "/bad"
			}
			args := []string{"-test.run=^TestUnsupportedSigningOptionsDoNotWriteOutput$", "--", "-key", keyPath, "-cert", certPath, "-input", input, "-output", output, "-no-tax", "-tsp-level", "signature", "-tsp", endpoint}
			if !tc.omitTrust {
				args = append(args, "-tsa-root", rootPath)
			}
			if tc.crypt {
				args = append(args, "-crypt", certPath, "-cipher", "kalyna256-ofb")
			}
			if tc.digest != "" {
				args = append(args, "-digest", tc.digest)
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "DSTU_TEST_SIGN_HELPER=1")
			diagnostics, err := cmd.CombinedOutput()
			if tc.bad || tc.omitTrust {
				require.Error(t, err)
				_, err = os.Stat(output)
				require.True(t, os.IsNotExist(err))
				return
			}
			require.NoError(t, err, string(diagnostics))
			document, err := os.ReadFile(output)
			require.NoError(t, err)
			if tc.crypt {
				envelope, err := cms.ParseEnveloped(document)
				require.NoError(t, err)
				require.Equal(t, cms.OIDKalyna256OFB, envelope.Algorithm)
				document, err = cms.DecryptEnveloped(envelope, key, leaf)
				require.NoError(t, err)
			}
			message, err := cms.VerifySignedRaw(document, nil, []*cert.Certificate{root})
			require.NoError(t, err)
			wantDigest := oid.GOST34311
			switch tc.digest {
			case "kupyna256":
				wantDigest = oid.Kupyna256
			case "kupyna512":
				wantDigest = oid.Kupyna512
			}
			require.Equal(t, wantDigest, testiit.SignerDigest(t, document))
			require.Equal(t, content, message.Content)
			tokens, err := message.SignatureTimestampTokens(0)
			require.NoError(t, err)
			require.Len(t, tokens, 1)
			signature, err := message.SignatureBytes(0)
			require.NoError(t, err)
			_, err = tsp.VerifySignatureTimestamp(tokens[0], signature, []*cert.Certificate{root}, time.Now())
			require.NoError(t, err)
		})
	}
}
