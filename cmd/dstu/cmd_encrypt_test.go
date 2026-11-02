package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func TestEncryptCLIProfiles(t *testing.T) {
	if os.Getenv("DSTU_TEST_ENCRYPT_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				runEncrypt(os.Args[i+1:])
				return
			}
		}
		os.Exit(2)
	}
	certificate, key := testpki.Issue(t, "CLI encryption", nil, nil, nil)
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		return path
	}
	keyPath, certPath := write("key.der", raw), write("certificate.cer", certificate.Raw)
	content := []byte("CLI encryption profile\x00\xff\r\nТест")
	input := write("input.txt", content)
	for _, name := range []string{"gost28147-cfb", "kalyna256-cfb", "kalyna256-ofb"} {
		t.Run(name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output.cms")
			cmd := exec.Command(os.Args[0], "-test.run=^TestEncryptCLIProfiles$", "--", "-cipher", name, "-key", keyPath, "-cert", certPath, "-crypt", certPath, "-input", input, "-output", output)
			cmd.Env = append(os.Environ(), "DSTU_TEST_ENCRYPT_HELPER=1")
			diagnostics, err := cmd.CombinedOutput()
			require.NoError(t, err, string(diagnostics))
			encoded, err := os.ReadFile(output)
			require.NoError(t, err)
			message, err := cms.ParseEnveloped(encoded)
			require.NoError(t, err)
			want := cms.OIDGost28147CFB
			if name == "kalyna256-cfb" {
				want = cms.OIDKalyna256CFB
			}
			if name == "kalyna256-ofb" {
				want = cms.OIDKalyna256OFB
			}
			require.Equal(t, want, message.Algorithm)
			plaintext, err := cms.DecryptEnveloped(message, key, certificate)
			require.NoError(t, err)
			require.Equal(t, content, plaintext)
		})
	}
}

func TestEncryptionCLIRejectsUnknownCipherBeforeIO(t *testing.T) {
	for _, operation := range []string{"encrypt", "sign"} {
		t.Run(operation, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output.cms")
			original := []byte("existing output")
			require.NoError(t, os.WriteFile(output, original, 0600))
			helper, environment := "TestEncryptCLIProfiles", "DSTU_TEST_ENCRYPT_HELPER=1"
			if operation == "sign" {
				helper, environment = "TestUnsupportedSigningOptionsDoNotWriteOutput", "DSTU_TEST_SIGN_HELPER=1"
			}
			cmd := exec.Command(os.Args[0], "-test.run=^"+helper+"$", "--", "-cipher", "aes256", "-key", "missing-key", "-output", output)
			cmd.Env = append(os.Environ(), environment)
			diagnostics, err := cmd.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(diagnostics), "unknown cipher")
			actual, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, original, actual)
		})
	}
}
