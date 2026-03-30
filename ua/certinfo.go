package ua

import (
	"errors"
	"time"

	"crypto-dstu/cert"
	"crypto-dstu/keystore"
)

// CertInfo holds human-readable fields extracted from a certificate.
type CertInfo struct {
	Serial       string
	Issuer       string
	Subject      string
	CommonName   string
	Organization string
	Title        string
	EDRPOU       string
	DRFO         string
	Email        string
	NotBefore    time.Time
	NotAfter     time.Time
	Role         cert.Role
	IsCA         bool
	Algorithm    string
	CurveName    string
}

// GetCertInfo parses a DER or PEM certificate and returns a CertInfo.
func GetCertInfo(der []byte) (*CertInfo, error) {
	der = keystore.MaybePEM(der)
	c, err := cert.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("ua: GetCertInfo: " + err.Error())
	}
	return certInfoFromCert(c), nil
}

// certInfoFromCert builds a CertInfo from an already-parsed Certificate.
func certInfoFromCert(c *cert.Certificate) *CertInfo {
	ci := cert.ExtractCertInfo(c)
	return &CertInfo{
		Serial:       ci.Serial,
		Issuer:       ci.Issuer,
		Subject:      ci.Subject,
		CommonName:   ci.CommonName,
		Organization: ci.Organization,
		Title:        ci.Title,
		EDRPOU:       ci.EDRPOU,
		DRFO:         ci.DRFO,
		Email:        ci.Email,
		NotBefore:    ci.NotBefore,
		NotAfter:     ci.NotAfter,
		Role:         cert.DetectRole(c),
		IsCA:         ci.IsCA,
		Algorithm:    ci.SigAlgOID,
		CurveName:    ci.CurveOID,
	}
}
