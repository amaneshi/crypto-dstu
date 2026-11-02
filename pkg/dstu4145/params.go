package dstu4145

import (
	"encoding/asn1"

	"github.com/amaneshi/crypto-dstu/pkg/ec"
)

// DomainParams bundles a curve with its OID and recommended hash OID.
type DomainParams struct {
	Name    string
	Curve   *ec.Curve
	OID     asn1.ObjectIdentifier // curve parameter OID
	HashOID asn1.ObjectIdentifier // associated signature+hash algorithm OID
}

// Ukrainian PKI OID arcs (DSTU 4145).
var (
	// OIDDstu4145WithGost34311 and related are signature+hash algorithm OIDs.
	OIDDstu4145WithGost34311    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1}
	OIDDstu4145ONBWithGost34311 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2}
	OIDDstu4145WithKupyna256    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 1, 1}
	OIDDstu4145WithKupyna512    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 6, 3, 1}

	// OIDCurvePB163 and related are curve parameter OIDs (index 0..9 maps to PB_163..PB_431).
	OIDCurvePB163 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 0}
	OIDCurvePB167 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 1}
	OIDCurvePB173 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 2}
	OIDCurvePB179 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 3}
	OIDCurvePB191 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 4}
	OIDCurvePB233 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 5}
	OIDCurvePB257 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 6}
	OIDCurvePB307 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 7}
	OIDCurvePB367 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 8}
	OIDCurvePB431 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 1, 2, 9}
)

var allParams = []DomainParams{
	{"DSTU_PB_163", ec.DSTU_PB_163(), OIDCurvePB163, OIDDstu4145WithGost34311},
	{"DSTU_PB_167", ec.DSTU_PB_167(), OIDCurvePB167, OIDDstu4145WithGost34311},
	{"DSTU_PB_173", ec.DSTU_PB_173(), OIDCurvePB173, OIDDstu4145WithGost34311},
	{"DSTU_PB_179", ec.DSTU_PB_179(), OIDCurvePB179, OIDDstu4145WithGost34311},
	{"DSTU_PB_191", ec.DSTU_PB_191(), OIDCurvePB191, OIDDstu4145WithGost34311},
	{"DSTU_PB_233", ec.DSTU_PB_233(), OIDCurvePB233, OIDDstu4145WithGost34311},
	{"DSTU_PB_257", ec.DSTU_PB_257(), OIDCurvePB257, OIDDstu4145WithGost34311},
	{"DSTU_PB_307", ec.DSTU_PB_307(), OIDCurvePB307, OIDDstu4145WithGost34311},
	{"DSTU_PB_367", ec.DSTU_PB_367(), OIDCurvePB367, OIDDstu4145WithGost34311},
	{"DSTU_PB_431", ec.DSTU_PB_431(), OIDCurvePB431, OIDDstu4145WithGost34311},
	{"DSTU_ONB_173", ec.DSTU_ONB_173(), asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 0}, OIDDstu4145ONBWithGost34311},
	{"DSTU_ONB_179", ec.DSTU_ONB_179(), asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 1}, OIDDstu4145ONBWithGost34311},
	{"DSTU_ONB_191", ec.DSTU_ONB_191(), asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 2}, OIDDstu4145ONBWithGost34311},
	{"DSTU_ONB_233", ec.DSTU_ONB_233(), asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 3}, OIDDstu4145ONBWithGost34311},
	{"DSTU_ONB_431", ec.DSTU_ONB_431(), asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 1, 2, 2, 4}, OIDDstu4145ONBWithGost34311},
}

// AllParams returns domain parameters for ten PB and five ONB DSTU curves.
func AllParams() []DomainParams {
	return allParams
}

// ParamsByName returns domain parameters for the named curve, or nil.
func ParamsByName(name string) *DomainParams {
	for i := range allParams {
		if allParams[i].Name == name {
			return &allParams[i]
		}
	}
	return nil
}

// ParamsByOID returns domain parameters for the given curve OID, or nil.
func ParamsByOID(oid asn1.ObjectIdentifier) *DomainParams {
	for i := range allParams {
		if allParams[i].OID.Equal(oid) {
			return &allParams[i]
		}
	}
	return nil
}
