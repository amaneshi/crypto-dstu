package tsp

import (
	"encoding/asn1"
	"math/big"
	"time"
)

// AlgorithmIdentifier mirrors pkix.AlgorithmIdentifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// PKIStatusInfo holds the TSP response status.
type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// Accuracy represents the accuracy of the timestamp.
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,implicit,tag:0"`
	Micros  int `asn1:"optional,implicit,tag:1"`
}

// TSTInfo is the inner signed content of a TimeStampToken (RFC 3161 §2.4.2).
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       Accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,implicit,tag:1"`
}

// OIDs used in TSP.
var (
	// OIDTSTInfo is the content type OID for TSTInfo (id-ct-TSTInfo).
	OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	// OIDSignatureTimeStamp is the unsigned attribute OID for a signature timestamp.
	OIDSignatureTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	// OIDContentTimeStamp is the unsigned attribute OID for a content timestamp.
	OIDContentTimeStamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 20}
)

// Status codes for PKIStatusInfo.
const (
	StatusGranted           = 0
	StatusGrantedWithMods   = 1
	StatusRejection         = 2
	StatusWaiting           = 3
	StatusRevocationWarning = 4
	StatusRevocationNotif   = 5
)
