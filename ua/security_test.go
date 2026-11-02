package ua

import (
	"bytes"
	"math/big"
	"testing"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/transport"
	"github.com/stretchr/testify/require"
)

func TestDecryptResolvesStaticSenderWithoutTrustingIt(t *testing.T) {
	b, recipientCert := makeBox(t)
	senderKey := mustGenerateKey(t)
	senderCert := makeCert(t, senderKey)
	senderCert.SerialNumber = new(big.Int).Add(senderCert.SerialNumber, big.NewInt(1))
	content := []byte("static sender plaintext")
	envelope, err := cms.EncryptWithOriginatorCertificate(content, []*cert.Certificate{recipientCert}, senderKey, senderCert)
	require.NoError(t, err)
	plain, err := b.DecryptDocument(envelope)
	require.ErrorContains(t, err, "originator certificate not found")
	require.Empty(t, plain)
	b.certificates = append(b.certificates, senderCert)
	plain, err = b.DecryptDocument(envelope)
	require.NoError(t, err)
	require.Equal(t, content, plain)
	require.Len(t, b.caCerts, 1)
	require.Same(t, recipientCert, b.caCerts[0])
}

func TestUnsignRejectsTamperingWithoutReturningContent(t *testing.T) {
	b, _ := makeBox(t)
	content := []byte("authenticated receipt")
	raw, err := b.SignDocument(content, SignOptions{NoTax: true})
	require.NoError(t, err)
	raw = bytes.Replace(raw, content, bytes.Repeat([]byte{'X'}, len(content)), 1)
	result, err := b.UnsignDocument(raw)
	require.Error(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.Content)
	require.False(t, result.Signers[0].Valid)
	require.Error(t, result.Signers[0].Error)
}

func TestUnsignRequiresExplicitTrustAndDetachedContent(t *testing.T) {
	b, c := makeBox(t)
	content := []byte("receipt")
	raw, err := b.SignDocument(content, SignOptions{NoTax: true, Detached: true})
	require.NoError(t, err)
	_, err = b.UnsignDocument(raw)
	require.Error(t, err)
	_, err = b.UnsignDocumentWithContent(raw, []byte("different"))
	require.Error(t, err)
	result, err := b.UnsignDocumentWithContent(raw, content)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
	b.caCerts = nil
	b.certificates = []*cert.Certificate{c}
	_, err = b.UnsignDocumentWithContent(raw, content)
	require.ErrorContains(t, err, "trust")
}

func TestEncryptedTaxOutputContainsOnlyProtectedPayload(t *testing.T) {
	b, c := makeBox(t)
	content := []byte("UNIQUE PRIVATE REPORT THAT MUST NOT APPEAR OUTSIDE ENCRYPTION")
	raw, err := b.signAndEncryptWithCert(content, c, SignOptions{})
	require.NoError(t, err)
	require.False(t, bytes.Contains(raw, content))
	container, err := transport.Decode(raw)
	require.NoError(t, err)
	require.Nil(t, container.FindSection("UA1_SIGN"))
	require.NotNil(t, container.FindSection("UA1_CRYPT"))
	signed, err := b.DecryptDocument(raw)
	require.NoError(t, err)
	result, err := b.UnsignDocument(signed)
	require.NoError(t, err)
	require.Equal(t, content, result.Content)
}

func TestRoleSelectionRejectsAmbiguity(t *testing.T) {
	b, _ := makeBox(t)
	other := mustGenerateKey(t)
	b.keys = append(b.keys, &keyEntry{privateKey: other, signCert: makeCert(t, other), role: cert.RoleDirector})
	_, err := b.firstKey()
	require.Error(t, err)
	require.NoError(t, b.SelectKeyByRole("director"))
	selected, err := b.firstKey()
	require.NoError(t, err)
	require.Same(t, other, selected.privateKey)
	require.Error(t, b.SelectKeyByRole("stamp"))
	b.keys = append(b.keys, b.keys[1])
	require.Error(t, b.SelectKeyByRole("director"))
}

func TestSeparateCertificateAssociationHonorsKeyUsage(t *testing.T) {
	b, c := makeBox(t)
	b.keys[0].signCert, b.keys[0].cryptCert = nil, nil
	b.caCerts = nil
	b.certificates = []*cert.Certificate{c}
	b.matchCertificates()
	require.Same(t, c, b.keys[0].signCert)
	require.Same(t, c, b.keys[0].cryptCert)
	require.Empty(t, b.caCerts)
	other := makeCert(t, mustGenerateKey(t))
	b.certificates = []*cert.Certificate{other}
	b.keys[0].signCert = nil
	b.matchCertificates()
	require.Nil(t, b.keys[0].signCert)
}
