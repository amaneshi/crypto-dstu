package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/testpki"
	"github.com/stretchr/testify/require"
)

func TestDecryptRequiredOCSPDoesNotReleaseRejectedContent(t *testing.T) {
	if os.Getenv("DSTU_TEST_DECRYPT_OCSP_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				runDecrypt(os.Args[i+1:])
				return
			}
		}
		os.Exit(2)
	}
	root, rootKey := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	leaf, key := testpki.Issue(t, "signer", root, rootKey, nil)
	content := []byte("CONFIDENTIAL VERIFIED RECEIPT\x00")
	signed, err := cms.Sign(content, key, leaf, cms.SignOptions{})
	require.NoError(t, err)
	encrypted, err := cms.Encrypt(signed, []*cert.Certificate{leaf}, key)
	require.NoError(t, err)
	keyDER, err := keystore.MarshalRawKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0600))
		return path
	}
	keyPath, leafPath, rootPath := write("key.der", keyDER), write("leaf.cer", leaf.Raw), write("root.cer", root.Raw)
	goodPath := write("good.ocsp", testpki.OCSP(t, leaf, root, root, rootKey, testpki.OCSPOptions{}))
	revokedPath := write("revoked.ocsp", testpki.OCSP(t, leaf, root, root, rootKey, testpki.OCSPOptions{Status: 1}))
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 9}})
	require.NoError(t, err)
	responder, responderKey := testpki.Issue(t, "responder", root, rootKey, []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: eku}})
	delegatedPath := write("delegated.ocsp", testpki.OCSP(t, leaf, root, responder, responderKey, testpki.OCSPOptions{}))
	crlPath := write("full.crl", testpki.CRL(t, root, rootKey, testpki.CRLOptions{}))
	revokedCRLPath := write("revoked.crl", testpki.CRL(t, root, rootKey, testpki.CRLOptions{Revoked: []pkix.RevokedCertificate{{SerialNumber: responder.SerialNumber, RevocationTime: time.Now().Add(-time.Hour)}}}))
	for _, tc := range []struct {
		name     string
		data     []byte
		evidence string
		crl      string
		pass     bool
	}{
		{"missing", signed, "", "", false}, {"revoked", signed, revokedPath, "", false},
		{"good", signed, goodPath, "", true}, {"encrypted missing", encrypted, "", "", false}, {"encrypted good", encrypted, goodPath, "", true},
		{"delegate missing proof", signed, delegatedPath, "", false},
		{"delegate good", signed, delegatedPath, crlPath, true},
		{"delegate revoked", signed, delegatedPath, revokedCRLPath, false},
		{"encrypted delegate good", encrypted, delegatedPath, crlPath, true},
		{"encrypted delegate revoked", encrypted, delegatedPath, revokedCRLPath, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := write(tc.name+".cms", tc.data)
			output := filepath.Join(t.TempDir(), "receipt.bin")
			args := []string{"-test.run=^TestDecryptRequiredOCSPDoesNotReleaseRejectedContent$", "--", "-key", keyPath, "-cert", leafPath, "-ca", rootPath, "-input", input, "-output", output, "-require-ocsp", "-v"}
			if tc.evidence != "" {
				args = append(args, "-ocsp-response", tc.evidence)
			}
			if tc.crl != "" {
				args = append(args, "-responder-crl", tc.crl)
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "DSTU_TEST_DECRYPT_OCSP_HELPER=1")
			diagnostics, err := cmd.CombinedOutput()
			if tc.pass {
				require.NoError(t, err, string(diagnostics))
				actual, err := os.ReadFile(output)
				require.NoError(t, err)
				require.Equal(t, content, actual)
				require.Contains(t, string(diagnostics), "revocation=good")
			} else {
				require.Error(t, err)
				_, err = os.Stat(output)
				require.True(t, os.IsNotExist(err))
				require.NotContains(t, string(diagnostics), string(content))
			}
		})
	}
}
