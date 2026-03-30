package cert

// Role identifies the certificate holder's role in the Ukrainian PKI.
// Reference: cryptonite pkix_cert.c role detection logic.
type Role string

const (
	RolePersonal Role = "personal" // natural person: DRFO present, no EDRPOU
	RoleFOP      Role = "fop"      // private entrepreneur: DRFO == EDRPOU (or natural-person EDRPOU range)
	RoleDirector Role = "director" // employee: DRFO present, different corporate EDRPOU
	RoleStamp    Role = "stamp"    // corporate seal: EDRPOU present, no DRFO
	RoleOther    Role = "other"    // ambiguous / unrecognised
)

// DetectRole classifies the certificate holder based on the presence and
// relationship between DRFO (personal tax ID) and EDRPOU (corporate code).
//
// Detection rules (aligned with cryptonite pkix_cert.c):
//
//	personal  — DRFO present, EDRPOU absent
//	stamp     — EDRPOU present, DRFO absent
//	fop       — both present, DRFO == EDRPOU  OR  EDRPOU is in natural-person range (10 digits)
//	director  — both present, EDRPOU is a corporate code (8 digits), EDRPOU != DRFO
//	other     — all other combinations
func DetectRole(cert *Certificate) Role {
	hasDRFO := cert.DRFO != ""
	hasEDRPOU := cert.EDRPOU != ""

	switch {
	case hasDRFO && !hasEDRPOU:
		return RolePersonal

	case !hasDRFO && hasEDRPOU:
		return RoleStamp

	case hasDRFO && hasEDRPOU:
		// FOP: DRFO equals EDRPOU (private entrepreneur registered as individual)
		if cert.DRFO == cert.EDRPOU {
			return RoleFOP
		}
		// FOP: EDRPOU is a 10-digit natural-person code matching DRFO format
		if len(cert.EDRPOU) == 10 && isDigits(cert.EDRPOU) {
			return RoleFOP
		}
		// Director: corporate EDRPOU (8 digits), different from DRFO
		if len(cert.EDRPOU) == 8 && isDigits(cert.EDRPOU) {
			return RoleDirector
		}
		return RoleOther

	default:
		return RoleOther
	}
}

// isDigits reports whether s consists entirely of ASCII decimal digits.
func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
