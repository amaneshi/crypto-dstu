package ua

import (
	"errors"

	"crypto-dstu/cert"
	"crypto-dstu/dstu4145"
	"crypto-dstu/keystore"
)

// VerifyCert validates a DER or PEM certificate against the Box CA pool.
func (b *Box) VerifyCert(der []byte) error {
	der = keystore.MaybePEM(der)
	c, err := cert.ParseCertificate(der)
	if err != nil {
		return errors.New("ua: VerifyCert: parse: " + err.Error())
	}
	if len(b.CACerts) == 0 {
		return cert.VerifyCert(c, c) // self-check validity only
	}
	return cert.VerifyCertChain(c, b.CACerts)
}

// VerifyCertPKMatch checks that a DER/PEM certificate matches a private key.
// Both the certificate and key data are parsed from their raw bytes.
func VerifyCertPKMatch(certDER []byte, keyData []byte, password string) error {
	certDER = keystore.MaybePEM(certDER)
	c, err := cert.ParseCertificate(certDER)
	if err != nil {
		return errors.New("ua: VerifyCertPKMatch: parse cert: " + err.Error())
	}

	result, err := keystore.Parse(keyData, password)
	if err != nil {
		return errors.New("ua: VerifyCertPKMatch: parse key: " + err.Error())
	}
	if len(result.Keys) == 0 {
		return errors.New("ua: VerifyCertPKMatch: no keys found")
	}
	return cert.VerifyCertPKMatch(c, result.Keys[0])
}

// VerifyCertPKMatchDirect checks that a certificate matches an already-parsed private key.
func VerifyCertPKMatchDirect(c *cert.Certificate, priv *dstu4145.PrivateKey) error {
	return cert.VerifyCertPKMatch(c, priv)
}
