package ua

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/amaneshi/crypto-dstu/internal/cert"
)

func TestCertificateAccessAndSeparateAgreementKey(t *testing.T) {
	box, c := makeBox(t)
	box.certificates = append(box.certificates, c)
	key := box.keys[0]
	other := mustGenerateKey(t)
	box.keys = append(box.keys, &keyEntry{privateKey: other, cryptCert: makeCert(t, other)})
	selected, err := box.firstKey()
	require.NoError(t, err)
	require.Same(t, key, selected)
	der, err := box.SigningCertificate()
	require.NoError(t, err)
	require.Equal(t, c.Raw, der)
	der[0] ^= 1
	require.NotEqual(t, c.Raw, der)
	certs := box.Certificates()
	require.Len(t, certs, 1)
	certs[0][0] ^= 1
	require.NotEqual(t, c.Raw, certs[0])
	_, err = NewBox().SigningCertificate()
	require.Error(t, err)
}

func TestSigningCertInfo(t *testing.T) {
	// A parsed CZO certificate whose key ID jkurwa computes as e1bcc73d… while
	// its SubjectKeyIdentifier is b756205e… (see internal/cert/keyid_test.go).
	der, err := os.ReadFile(filepath.FromSlash("../internal/ocsp/testdata/czo-2025/subject.cer"))
	require.NoError(t, err)
	signCert, err := cert.ParseCertificate(der)
	require.NoError(t, err)
	box := NewBox()
	box.keys = []*keyEntry{{privateKey: mustGenerateKey(t), signCert: signCert}}
	info, err := box.SigningCertInfo()
	require.NoError(t, err)
	const keyID = "e1bcc73d9a160a4df8e66a4e90333f695f3dd333674d1bc67d09ef70ab5d788e"
	require.Equal(t, keyID, info.KeyID)
	require.Equal(t, signCert.NotAfter, info.NotAfter)

	fromDER, err := GetCertInfo(der)
	require.NoError(t, err)
	require.Equal(t, info, fromDER, "SigningCertInfo and GetCertInfo must agree")

	other := mustGenerateKey(t)
	box.keys = append(box.keys, &keyEntry{privateKey: other, signCert: makeCert(t, other)})
	_, err = box.SigningCertInfo()
	require.Error(t, err, "two signing identities without a role selection")

	_, err = NewBox().SigningCertInfo()
	require.Error(t, err)

	unmatched := NewBox()
	unmatched.keys = []*keyEntry{{privateKey: mustGenerateKey(t)}}
	_, err = unmatched.SigningCertInfo()
	require.Error(t, err)

	noPublicKeyBytes, _ := makeBox(t)
	info, err = noPublicKeyBytes.SigningCertInfo()
	require.NoError(t, err)
	require.Empty(t, info.KeyID)
}
