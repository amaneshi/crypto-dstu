package ua

import (
	"errors"
	"time"

	"crypto-dstu/cert"
	"crypto-dstu/keystore"
)

// CertInfo holds human-readable fields extracted from a certificate.
type CertInfo struct {
	Serial       string    `json:"serial"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	CommonName   string    `json:"commonName"`
	Organization string    `json:"organization"`
	Title        string    `json:"title"`
	EDRPOU       string    `json:"edrpou"`
	DRFO         string    `json:"drfo"`
	Email        string    `json:"email"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	Role         cert.Role `json:"role"`
	IsCA         bool      `json:"isCA"`
	Algorithm    string    `json:"algorithm"`
	CurveName    string    `json:"curveName"`
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
