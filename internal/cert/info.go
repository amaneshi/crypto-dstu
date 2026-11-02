package cert

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/oid"
)

// CertInfo holds human-readable extracted fields from a Certificate.
type CertInfo struct { //nolint:revive // CertInfo is established public API; renaming to Info would be a breaking change
	Serial             string
	Issuer             string
	Subject            string
	EDRPOU             string
	DRFO               string
	IPN                string
	Email              string
	CommonName         string
	Organization       string
	OrganizationalUnit string
	GivenName          string
	Surname            string
	Title              string
	Country            string
	Locality           string
	State              string
	NotBefore          time.Time
	NotAfter           time.Time
	IsCA               bool
	KeyUsage           []string
	CurveOID           string
	SigAlgOID          string
}

// GetCertInfo parses a DER certificate and returns a CertInfo summary.
func GetCertInfo(der []byte) (*CertInfo, error) {
	c, err := ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return ExtractCertInfo(c), nil
}

// ExtractCertInfo builds a CertInfo from an already-parsed Certificate.
func ExtractCertInfo(c *Certificate) *CertInfo {
	ci := &CertInfo{
		EDRPOU:             c.EDRPOU,
		DRFO:               c.DRFO,
		IPN:                c.IPN,
		Email:              c.Email,
		CommonName:         c.CommonName,
		Organization:       c.Organization,
		OrganizationalUnit: c.OrganizationalUnit,
		GivenName:          c.GivenName,
		Surname:            c.Surname,
		Title:              c.Title,
		Country:            c.Country,
		Locality:           c.Locality,
		State:              c.State,
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		SigAlgOID:          oid.AlgorithmName(c.SigAlgOID),
	}

	if c.SerialNumber != nil {
		ci.Serial = fmt.Sprintf("%X", c.SerialNumber)
	}

	ci.Issuer = formatRDNBytes(c.Issuer.Bytes)
	ci.Subject = formatRDNBytes(c.Subject.Bytes)

	// Curve OID from public key algorithm
	if c.PublicKey != nil && c.PublicKey.Curve != nil {
		// Find the OID for this curve via dstu4145 params
		ci.CurveOID = curveName(c)
	}

	// Parse extensions
	for _, ext := range c.Extensions {
		switch {
		case ext.Id.Equal(oid.OIDExtBasicConstraints):
			ci.IsCA = parseBasicConstraintsIsCA(ext.Value)
		case ext.Id.Equal(oid.OIDExtKeyUsage):
			ci.KeyUsage = parseKeyUsage(ext.Value)
		}
	}

	return ci
}

// formatRDNBytes converts raw DN bytes to a simple hex string (best-effort).
func formatRDNBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}

// curveName returns the curve name string for a certificate's public key.
func curveName(c *Certificate) string {
	if c.PublicKey == nil || c.PublicKey.Curve == nil {
		return ""
	}
	curve := c.PublicKey.Curve
	// Match against all DSTU params
	allCurveOIDs := map[int]string{
		163: "DSTU_PB_163",
		167: "DSTU_PB_167",
		173: "DSTU_PB_173",
		179: "DSTU_PB_179",
		191: "DSTU_PB_191",
		233: "DSTU_PB_233",
		257: "DSTU_PB_257",
		307: "DSTU_PB_307",
		367: "DSTU_PB_367",
		431: "DSTU_PB_431",
	}
	if name, ok := allCurveOIDs[curve.M]; ok {
		return name
	}
	return fmt.Sprintf("unknown(m=%d)", curve.M)
}

// parseBasicConstraintsIsCA parses the BasicConstraints extension value.
// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }.
func parseBasicConstraintsIsCA(val []byte) bool {
	if len(val) == 0 {
		return false
	}
	// The Value field is already the OCTET STRING content (inner DER)
	// BasicConstraints SEQUENCE { cA BOOLEAN }
	if len(val) >= 5 && val[0] == 0x30 {
		// SEQUENCE { BOOLEAN }
		// 0x30 len 0x01 len 0xFF/0x00
		for i := 2; i < len(val)-2; i++ {
			if val[i] == 0x01 && val[i+1] == 0x01 {
				return val[i+2] != 0x00
			}
		}
	}
	return false
}

// parseKeyUsage parses the KeyUsage extension bit string into named usages.
func parseKeyUsage(val []byte) []string {
	if len(val) < 4 {
		return nil
	}
	// BIT STRING: 0x03 len unusedBits bits...
	if val[0] != 0x03 || len(val) < 4 {
		return nil
	}
	unusedBits := int(val[2])
	bits := val[3]

	names := []string{
		"digitalSignature",
		"nonRepudiation",
		"keyEncipherment",
		"dataEncipherment",
		"keyAgreement",
		"keyCertSign",
		"cRLSign",
		"encipherOnly",
	}
	var usage []string
	for i := range 8 - unusedBits {
		if bits&(0x80>>uint(i)) != 0 {
			if i < len(names) {
				usage = append(usage, names[i])
			}
		}
	}
	return usage
}
