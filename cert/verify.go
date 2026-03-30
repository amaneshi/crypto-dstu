package cert

import (
	"errors"
	"time"

	"crypto-dstu/dstu4145"
	"crypto-dstu/gost34311"
	"crypto-dstu/kupyna"
	"crypto-dstu/oid"
)

// VerifyCert verifies cert's signature using issuerCert's public key.
// It also checks the validity period.
// Reference: cryptonite pkix_verify.c
func VerifyCert(cert *Certificate, issuerCert *Certificate) error {
	if err := checkValidity(cert, time.Now()); err != nil {
		return err
	}
	return verifySignature(cert, issuerCert.PublicKey)
}

// VerifyCertChain verifies cert against a set of trusted root certificates.
// It searches roots for a certificate whose subject matches cert's issuer and
// whose public key verifies cert's signature.
func VerifyCertChain(cert *Certificate, roots []*Certificate) error {
	if err := checkValidity(cert, time.Now()); err != nil {
		return err
	}
	for _, root := range roots {
		if rawEqual(root.Subject.Bytes, cert.Issuer.Bytes) {
			if err := verifySignature(cert, root.PublicKey); err == nil {
				return nil
			}
		}
	}
	return errors.New("cert: VerifyCertChain: no trusted root found for issuer")
}

// VerifyCertPKMatch checks that the private key corresponds to the certificate's public key.
// It derives the public key from priv and compares with cert.PublicKey.
func VerifyCertPKMatch(cert *Certificate, priv *dstu4145.PrivateKey) error {
	if cert.PublicKey == nil {
		return errors.New("cert: VerifyCertPKMatch: certificate has no public key")
	}
	derived := priv.Public()
	// Compare by X coordinate only: DSTU certificates store only x (compressed form),
	// so the expanded y may differ from the original depending on the fsquad solution.
	if !derived.Q.X.Equal(cert.PublicKey.Q.X) {
		return errors.New("cert: VerifyCertPKMatch: private key does not match certificate public key")
	}
	return nil
}

// checkValidity returns an error if now is outside [cert.NotBefore, cert.NotAfter].
func checkValidity(cert *Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return errors.New("cert: certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return errors.New("cert: certificate has expired")
	}
	return nil
}

// verifySignature verifies cert's signature over cert.TBSRaw using pub.
// The hash algorithm is determined from cert.SigAlgOID.
func verifySignature(cert *Certificate, pub *dstu4145.PublicKey) error {
	if pub == nil {
		return errors.New("cert: verifySignature: issuer has no DSTU public key")
	}

	digest, err := hashTBS(cert)
	if err != nil {
		return err
	}

	sig, err := dstu4145.UnmarshalSignature(cert.Signature, pub.Curve.Words)
	if err != nil {
		return errors.New("cert: verifySignature: unmarshal signature: " + err.Error())
	}

	if !dstu4145.Verify(pub, digest, sig) {
		return errors.New("cert: verifySignature: signature verification failed")
	}
	return nil
}

// hashTBS hashes cert.TBSRaw with the algorithm indicated by cert.SigAlgOID.
func hashTBS(cert *Certificate) ([]byte, error) {
	sigAlg := cert.SigAlgOID

	switch {
	case sigAlg.Equal(oid.DSTU4145WithGOST34311):
		h := gost34311.New()
		h.Write(cert.TBSRaw)
		return h.Sum(nil), nil

	case sigAlg.Equal(oid.DSTU4145WithKupyna256):
		h := kupyna.New256()
		h.Write(cert.TBSRaw)
		return h.Sum(nil), nil

	case sigAlg.Equal(oid.DSTU4145WithKupyna512):
		h := kupyna.New512()
		h.Write(cert.TBSRaw)
		return h.Sum(nil), nil

	default:
		return nil, errors.New("cert: unsupported signature algorithm: " + sigAlg.String())
	}
}

// rawEqual reports whether two byte slices are equal.
func rawEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
