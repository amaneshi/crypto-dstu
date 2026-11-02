package ua

import (
	"context"
	"errors"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
)

// VerifyCert validates a DER or PEM certificate against the Box CA pool.
func (b *Box) VerifyCert(der []byte) error {
	return b.VerifyCertWithOptions(context.Background(), der, VerificationOptions{})
}

// VerifyCertWithOptions validates trust and the requested current-time OCSP policy.
func (b *Box) VerifyCertWithOptions(ctx context.Context, der []byte, options VerificationOptions) error {
	if ctx == nil {
		return errors.New("ua: verification context is required")
	}
	options, err := options.normalized()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	der = keystore.MaybePEM(der)
	c, err := cert.ParseCertificate(der)
	if err != nil {
		return errors.New("ua: VerifyCert: parse: " + err.Error())
	}
	if len(b.caCerts) == 0 {
		return errors.New("ua: VerifyCert: no trusted CA certificates configured")
	}
	if err := cert.VerifyCertChainWithIntermediates(c, b.caCerts, b.certificates); err != nil {
		return err
	}
	_, err = b.checkRevocation(ctx, c, b.certificates, options)
	return err
}

// VerifyCertPKMatch checks that a DER/PEM certificate matches a private key container.
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
