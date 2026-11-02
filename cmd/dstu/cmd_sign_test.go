package main

import (
	"bytes"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/transport"
	"github.com/stretchr/testify/require"
)

func TestSigningDigestCLI(t *testing.T) {
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", root, rootKey, nil)
	directory := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(directory, name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		return path
	}
	raw, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	keyPath, certPath := write("key.der", raw), write("leaf.cer", leaf.Raw)
	content := []byte("CLI signing profile\x00\xff\r\nТест")
	input := write("input.txt", content)
	for _, profile := range []struct {
		name   string
		digest asn1.ObjectIdentifier
	}{
		{"default", oid.GOST34311},
		{"auto", oid.GOST34311},
		{"gost34311", oid.GOST34311},
		{"kupyna256", oid.Kupyna256},
		{"kupyna512", oid.Kupyna512},
	} {
		t.Run(profile.name, func(t *testing.T) {
			for _, mode := range []string{"attached", "detached", "transport", "encrypted"} {
				t.Run(mode, func(t *testing.T) {
					output := filepath.Join(t.TempDir(), "output.cms")
					args := []string{
						"-test.run=^TestUnsupportedSigningOptionsDoNotWriteOutput$", "--",
						"-key", keyPath, "-cert", certPath, "-input", input, "-output", output,
					}
					if profile.name != "default" {
						args = append(args, "-digest", profile.name)
					}
					if mode != "transport" {
						args = append(args, "-no-tax")
					}
					if mode == "detached" {
						args = append(args, "-detached")
					}
					if mode == "encrypted" {
						args = append(args, "-crypt", certPath, "-cipher", "kalyna256-cfb")
					}
					cmd := exec.Command(os.Args[0], args...)
					cmd.Env = append(os.Environ(), "DSTU_TEST_SIGN_HELPER=1")
					diagnostics, err := cmd.CombinedOutput()
					require.NoError(t, err, string(diagnostics))
					document, err := os.ReadFile(output)
					require.NoError(t, err)
					switch mode {
					case "encrypted":
						envelope, err := cms.ParseEnveloped(document)
						require.NoError(t, err)
						require.Equal(t, cms.OIDKalyna256CFB, envelope.Algorithm)
						document, err = cms.DecryptEnveloped(envelope, key, leaf)
						require.NoError(t, err)
					case "transport":
						container, err := transport.Decode(document)
						require.NoError(t, err)
						section := container.FindSection("UA1_SIGN")
						require.NotNil(t, section)
						document = section.Contents
					}
					require.Equal(t, profile.digest, testiit.SignerDigest(t, document))
					message, err := cms.VerifySignedRaw(document, content, []*cert.Certificate{root})
					require.NoError(t, err)
					require.True(t, message.Signers[0].Valid)
					if mode != "detached" {
						require.Equal(t, content, message.Content)
					}
				})
			}
		})
	}
}

func TestUnknownSigningDigestLeavesOutputUntouched(t *testing.T) {
	for _, outputExists := range []bool{false, true} {
		t.Run(map[bool]string{false: "new file", true: "existing file"}[outputExists], func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "signature.cms")
			original := []byte("existing output")
			if outputExists {
				require.NoError(t, os.WriteFile(output, original, 0600))
			}
			cmd := exec.Command(os.Args[0],
				"-test.run=^TestUnsupportedSigningOptionsDoNotWriteOutput$", "--",
				"-digest", "sha256", "-key", "missing-key.dat", "-input", "missing-input.txt", "-output", output,
			)
			cmd.Env = append(os.Environ(), "DSTU_TEST_SIGN_HELPER=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			require.Error(t, cmd.Run())
			require.Empty(t, stdout.String())
			require.Contains(t, stderr.String(), `unknown digest "sha256"`)
			require.NotContains(t, stderr.String(), "sign setup")
			data, err := os.ReadFile(output)
			if outputExists {
				require.NoError(t, err)
				require.Equal(t, original, data)
			} else {
				require.True(t, os.IsNotExist(err))
			}
		})
	}
}
