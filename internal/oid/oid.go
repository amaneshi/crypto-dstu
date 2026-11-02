package oid

import "encoding/asn1"

// Ukrainian PKI OID root: 1.2.804.2.1.1.1
// Source: cryptonite pkix.h, DSTU 4145-2002, certificate format regulation
// http://zakon4.rada.gov.ua/laws/show/z1398-12

// Signature algorithm OIDs.
var (
	DSTU4145WithGOST34311    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	DSTU4145ONBWithGOST34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2}
	DSTU4145WithKupyna256    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 1, 1}
	DSTU4145WithKupyna512    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 3, 1}
)

// Named curve OIDs (index 0..9 → PB_163..PB_431).
var (
	CurvePB163 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 0}
	CurvePB167 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 1}
	CurvePB173 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 2}
	CurvePB179 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 3}
	CurvePB191 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 4}
	CurvePB233 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 5}
	CurvePB257 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}
	CurvePB307 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 7}
	CurvePB367 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 8}
	CurvePB431 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 9}
)

// GOST 28147-89 cipher OIDs.
var (
	GOST28147     = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}
	GOST28147CFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3, 1}
	GOST28147Wrap = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3, 2}
)

// Hash algorithm OIDs.
var (
	GOST34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 1}
	Kupyna256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1}
	Kupyna384 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 2}
	Kupyna512 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 3}
)

// Subject DN attribute OIDs — Ukrainian PKI specific.
var (
	// EDRPOU — Єдиний державний реєстр підприємств і організацій України
	// Corporate identification code (8 digits).
	EDRPOU = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 1, 1}

	// DRFO — Державний реєстр фізичних осіб
	// Personal tax identification number (10 digits).
	DRFO = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 1, 2}

	// IPN — alternative tax number attribute.
	IPN = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 11, 1, 4, 2, 1}
)

// Standard X.509 attribute OIDs referenced in Ukrainian certificates.
var (
	OIDCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	OIDCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	OIDState              = asn1.ObjectIdentifier{2, 5, 4, 8}
	OIDTitle              = asn1.ObjectIdentifier{2, 5, 4, 12}
	OIDSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	OIDEmailAddress       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	OIDGivenName          = asn1.ObjectIdentifier{2, 5, 4, 42}
	OIDSurname            = asn1.ObjectIdentifier{2, 5, 4, 4}
)

// X.509 extension OIDs.
var (
	OIDExtSubjectKeyID        = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDExtBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDExtAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDExtExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDExtCRLDistributionPts  = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDExtAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDExtCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
)

// curveNames maps curve OID string → human-readable name.
var curveNames = map[string]string{
	CurvePB163.String():           "DSTU_PB_163",
	CurvePB167.String():           "DSTU_PB_167",
	CurvePB173.String():           "DSTU_PB_173",
	CurvePB179.String():           "DSTU_PB_179",
	CurvePB191.String():           "DSTU_PB_191",
	CurvePB233.String():           "DSTU_PB_233",
	CurvePB257.String():           "DSTU_PB_257",
	CurvePB307.String():           "DSTU_PB_307",
	CurvePB367.String():           "DSTU_PB_367",
	CurvePB431.String():           "DSTU_PB_431",
	"1.2.804.2.1.1.1.1.3.1.2.2.0": "DSTU_ONB_173",
	"1.2.804.2.1.1.1.1.3.1.2.2.1": "DSTU_ONB_179",
	"1.2.804.2.1.1.1.1.3.1.2.2.2": "DSTU_ONB_191",
	"1.2.804.2.1.1.1.1.3.1.2.2.3": "DSTU_ONB_233",
	"1.2.804.2.1.1.1.1.3.1.2.2.4": "DSTU_ONB_431",
}

// algorithmNames maps algorithm OID string → human-readable name.
var algorithmNames = map[string]string{
	DSTU4145WithGOST34311.String():    "DSTU4145-with-GOST34311",
	DSTU4145ONBWithGOST34311.String(): "DSTU4145-ONB-with-GOST34311",
	DSTU4145WithKupyna256.String():    "DSTU4145-with-Kupyna256",
	DSTU4145WithKupyna512.String():    "DSTU4145-with-Kupyna512",
	GOST34311.String():                "GOST34311",
	Kupyna256.String():                "Kupyna-256",
	Kupyna384.String():                "Kupyna-384",
	Kupyna512.String():                "Kupyna-512",
	GOST28147.String():                "GOST28147",
	GOST28147CFB.String():             "GOST28147-CFB",
	GOST28147Wrap.String():            "GOST28147-Wrap",
}

// CurveNameByOID returns the human-readable curve name for an OID, or "".
func CurveNameByOID(o asn1.ObjectIdentifier) string {
	return curveNames[o.String()]
}

// AlgorithmName returns the human-readable algorithm name for an OID, or the OID string.
func AlgorithmName(o asn1.ObjectIdentifier) string {
	if name, ok := algorithmNames[o.String()]; ok {
		return name
	}
	return o.String()
}

// IsCurveOID reports whether o is one of the supported standard PB/ONB curve OIDs.
func IsCurveOID(o asn1.ObjectIdentifier) bool {
	_, ok := curveNames[o.String()]
	return ok
}

// IsDSTU4145SigAlg reports whether o is one of the DSTU 4145 signature algorithm OIDs.
func IsDSTU4145SigAlg(o asn1.ObjectIdentifier) bool {
	return o.Equal(DSTU4145WithGOST34311) ||
		o.Equal(DSTU4145ONBWithGOST34311) ||
		o.Equal(DSTU4145WithKupyna256) ||
		o.Equal(DSTU4145WithKupyna512)
}
