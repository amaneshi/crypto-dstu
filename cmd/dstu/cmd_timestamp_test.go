package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/testpki"
	"crypto-dstu/internal/testtimestamp"
	"github.com/stretchr/testify/require"
)

func TestDecryptRequiredTimestampControlsOutput(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", root, rootKey, nil)
	tsa, tsaKey := testpki.Issue(t, "TSA", root, rootKey, testtimestamp.Extensions(t))
	content := []byte("TIMESTAMP PROTECTED RECEIPT")
	signed, err := cms.Sign(content, key, leaf, cms.SignOptions{})
	require.NoError(t, err)
	msg, err := cms.ParseSigned(signed)
	require.NoError(t, err)
	signature, err := msg.SignatureBytes(0)
	require.NoError(t, err)
	good := testtimestamp.Attach(t, signed, testtimestamp.Token(t, signature, tsa, tsaKey, nil))
	bad := testtimestamp.Attach(t, signed, testtimestamp.Token(t, content, tsa, tsaKey, nil))
	encrypted, err := cms.Encrypt(good, []*cert.Certificate{leaf}, key)
	require.NoError(t, err)
	encryptedBad, err := cms.Encrypt(bad, []*cert.Certificate{leaf}, key)
	require.NoError(t, err)
	keyDER, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		return path
	}
	keyPath, certPath, rootPath := write("key.der", keyDER), write("leaf.cer", leaf.Raw), write("root.cer", root.Raw)
	for _, tc := range []struct {
		name string
		data []byte
		pass bool
	}{{"good", good, true}, {"bad", bad, false}, {"missing", signed, false}, {"encrypted good", encrypted, true}, {"encrypted bad", encryptedBad, false}} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "receipt.bin")
			args := []string{"-test.run=^TestDecryptRequiredOCSPDoesNotReleaseRejectedContent$", "--", "-key", keyPath, "-cert", certPath, "-ca", rootPath, "-input", write(tc.name+".cms", tc.data), "-output", output, "-require-timestamp", "-tsa-root", rootPath, "-v"}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "DSTU_TEST_DECRYPT_OCSP_HELPER=1")
			diagnostics, err := cmd.CombinedOutput()
			if tc.pass {
				require.NoError(t, err, string(diagnostics))
				actual, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, content, actual)
				require.Contains(t, string(diagnostics), "type=signature valid=true")
			} else {
				require.Error(t, err)
				_, err := os.Stat(output)
				require.True(t, os.IsNotExist(err))
				require.NotContains(t, string(diagnostics), string(content))
			}
		})
	}
}
