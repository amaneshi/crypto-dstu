package ua

import (
	"testing"

	"github.com/stretchr/testify/require"
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
